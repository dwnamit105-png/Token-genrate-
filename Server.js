const express = require('express');
const axios = require('axios');
const qs = require('qs');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Facebook/Meta App Credentials
const APP_CONFIG = {
    messenger_ios: {
        client_id: '447188370370048',
        client_secret: 'af41071a4bafe5fb8c87b3f7c7b7f3b4',
        access_token: '447188370370048|af41071a4bafe5fb8c87b3f7c7b7f3b4',
        user_agent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [FBAN/MessengerForiOS;FBAV/450.0;FBBV/450.0;FBDV/iPhone15,3;FBMD/iPhone;FBSN/iOS;FBSV/17.0;FBSS/3;FBID/phone;FBLC/en_US;FBOP/5;FBRV/0]'
    },
    fb_android: {
        client_id: '350685531728',
        client_secret: 'c1e620fa708a1d5696fb991c1bde5662',
        access_token: '350685531728|c1e620fa708a1d5696fb991c1bde5662',
        user_agent: 'Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36'
    }
};

class TokenGenerator {
    constructor() {
        this.session = axios.create({
            headers: {
                'User-Agent': APP_CONFIG.messenger_ios.user_agent,
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive'
            },
            timeout: 30000
        });
    }

    /**
     * Main function to get EAAD6V7 token
     */
    async getEAAD6V7Token(email, password, method = 'login', recoveryCode = null) {
        try {
            console.log(`Starting token generation via ${method}...`);
            
            let universalToken;
            
            if (method === 'login') {
                // Login with email/password
                universalToken = await this.loginWithCredentials(email, password);
            } else if (method === 'recovery') {
                // Password forgot code method
                universalToken = await this.loginWithRecoveryCode(email, recoveryCode);
            } else {
                throw new Error('Invalid method');
            }
            
            if (!universalToken) {
                throw new Error('Failed to get universal token');
            }
            
            console.log('Universal token obtained, converting to EAAD6V7...');
            
            // Convert to EAAD6V7 format
            const eaaToken = await this.convertToEAAD6V7(universalToken);
            
            // Validate token
            const tokenInfo = await this.validateToken(eaaToken);
            
            return {
                success: true,
                universal_token: universalToken,
                eaadv7_token: eaaToken,
                token_type: 'EAAD6V7',
                user_id: tokenInfo.user_id,
                app_id: tokenInfo.app_id,
                expires_at: tokenInfo.expires_at,
                scopes: tokenInfo.scopes || [],
                is_valid: tokenInfo.is_valid,
                generated_at: new Date().toISOString()
            };
            
        } catch (error) {
            console.error('Error:', error.message);
            return {
                success: false,
                error: error.message,
                error_code: error.code || 'TOKEN_GEN_FAILED'
            };
        }
    }

    /**
     * Login with email/phone + password
     */
    async loginWithCredentials(email, password) {
        try {
            // Step 1: Get initial parameters
            const params = await this.getLoginParams();
            
            // Step 2: Prepare login data
            const loginData = {
                lsd: params.lsd,
                jazoest: params.jazoest,
                m_ts: params.m_ts,
                li: params.li,
                try_number: '0',
                unrecognized_tries: '0',
                email: email,
                pass: password,
                login: 'Log In',
                bi_xrwh: '0',
                fb_dtsg: params.fb_dtsg
            };
            
            // Step 3: Login request
            const response = await this.session.post(
                'https://www.facebook.com/login/device-based/regular/login/',
                qs.stringify(loginData),
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Origin': 'https://www.facebook.com',
                        'Referer': 'https://www.facebook.com/',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                    },
                    maxRedirects: 5
                }
            );
            
            // Step 4: Extract token from response
            const token = this.extractTokenFromResponse(response.data);
            
            if (!token) {
                throw new Error('Login successful but token not found');
            }
            
            return token;
            
        } catch (error) {
            throw new Error(`Login failed: ${error.message}`);
        }
    }

    /**
     * Login with password recovery code
     */
    async loginWithRecoveryCode(email, recoveryCode) {
        try {
            // Step 1: Request password reset
            await this.requestPasswordReset(email);
            
            // Step 2: Submit recovery code
            const resetToken = await this.submitRecoveryCode(email, recoveryCode);
            
            // Step 3: Set new password (generate random)
            const newPassword = this.generateRandomPassword();
            await this.setNewPassword(resetToken, newPassword);
            
            // Step 4: Login with new credentials
            return await this.loginWithCredentials(email, newPassword);
            
        } catch (error) {
            throw new Error(`Recovery login failed: ${error.message}`);
        }
    }

    /**
     * Get initial login parameters
     */
    async getLoginParams() {
        const response = await this.session.get('https://www.facebook.com');
        const html = response.data;
        
        const extractValue = (regex) => {
            const match = html.match(regex);
            return match ? match[1] : '';
        };
        
        return {
            lsd: extractValue(/name="lsd" value="([^"]+)"/),
            jazoest: extractValue(/name="jazoest" value="([^"]+)"/),
            m_ts: extractValue(/name="m_ts" value="([^"]+)"/),
            li: extractValue(/name="li" value="([^"]+)"/),
            fb_dtsg: extractValue(/name="fb_dtsg" value="([^"]+)"/) || 
                     extractValue(/"DTSGInitData",\[\],{"token":"([^"]+)"}/)
        };
    }

    /**
     * Extract token from HTML response
     */
    extractTokenFromResponse(html) {
        const tokenPatterns = [
            /access_token=([^&]+)/,
            /"accessToken":"([^"]+)"/,
            /"token":"([^"]+)"/,
            /EAAD[UV6][A-Za-z0-9._-]{150,300}/,
            /"EAAD[^"]+"/,
            /accessToken=([^&\s]+)/
        ];
        
        for (const pattern of tokenPatterns) {
            const match = html.match(pattern);
            if (match) {
                const token = match[1] ? match[1].replace(/"/g, '') : match[0].replace(/"/g, '');
                if (token.length > 100) {
                    return token;
                }
            }
        }
        
        return null;
    }

    /**
     * Convert universal token to EAAD6V7 format
     */
    async convertToEAAD6V7(universalToken) {
        try {
            // Method 1: Graph API exchange
            const response = await axios.get(
                'https://graph.facebook.com/v6.0/oauth/access_token',
                {
                    params: {
                        grant_type: 'fb_exchange_token',
                        client_id: APP_CONFIG.messenger_ios.client_id,
                        client_secret: APP_CONFIG.messenger_ios.client_secret,
                        fb_exchange_token: universalToken
                    }
                }
            );
            
            const exchangedToken = response.data.access_token;
            
            // Check if it's EAAD6 format
            if (exchangedToken.startsWith('EAAD6')) {
                return exchangedToken;
            }
            
            // Method 2: Get page token (often EAAD6 format)
            const pageToken = await this.getPageAccessToken(exchangedToken);
            if (pageToken && pageToken.startsWith('EAAD6')) {
                return pageToken;
            }
            
            // Method 3: Try direct Graph API v6.0
            const v6Response = await axios.get(
                'https://graph.facebook.com/v6.0/me',
                {
                    params: {
                        access_token: exchangedToken,
                        fields: 'id'
                    }
                }
            );
            
            // If API v6.0 works, token is compatible
            if (v6Response.data.id) {
                return exchangedToken;
            }
            
            return universalToken;
            
        } catch (error) {
            console.warn('EAAD6V7 conversion failed:', error.message);
            return universalToken;
        }
    }

    /**
     * Get page access token
     */
    async getPageAccessToken(userToken) {
        try {
            const response = await axios.get(
                'https://graph.facebook.com/v6.0/me/accounts',
                {
                    params: {
                        access_token: userToken,
                        fields: 'access_token'
                    }
                }
            );
            
            if (response.data.data && response.data.data.length > 0) {
                return response.data.data[0].access_token;
            }
            return null;
        } catch (error) {
            return null;
        }
    }

    /**
     * Validate token
     */
    async validateToken(token) {
        try {
            const response = await axios.get(
                'https://graph.facebook.com/debug_token',
                {
                    params: {
                        input_token: token,
                        access_token: `${APP_CONFIG.messenger_ios.client_id}|${APP_CONFIG.messenger_ios.client_secret}`
                    }
                }
            );
            
            return {
                is_valid: response.data.data.is_valid,
                app_id: response.data.data.app_id,
                user_id: response.data.data.user_id,
                expires_at: response.data.data.expires_at,
                scopes: response.data.data.scopes || []
            };
        } catch (error) {
            return {
                is_valid: false,
                error: error.message
            };
        }
    }

    /**
     * Request password reset
     */
    async requestPasswordReset(email) {
        const params = await this.getLoginParams();
        
        const resetData = {
            lsd: params.lsd,
            email: email,
            did_submit: 'Search',
            fb_dtsg: params.fb_dtsg
        };
        
        await this.session.post(
            'https://www.facebook.com/login/identify/',
            qs.stringify(resetData),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Origin': 'https://www.facebook.com'
                }
            }
        );
    }

    /**
     * Submit recovery code
     */
    async submitRecoveryCode(email, code) {
        const params = await this.getLoginParams();
        
        const codeData = {
            lsd: params.lsd,
            n: code,
            save_new_password: '1',
            fb_dtsg: params.fb_dtsg
        };
        
        const response = await this.session.post(
            'https://www.facebook.com/recover/code/',
            qs.stringify(codeData),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );
        
        // Extract reset token
        const tokenMatch = response.data.match(/name="reset_token" value="([^"]+)"/);
        return tokenMatch ? tokenMatch[1] : null;
    }

    /**
     * Set new password
     */
    async setNewPassword(resetToken, newPassword) {
        const params = await this.getLoginParams();
        
        const passwordData = {
            lsd: params.lsd,
            reset_token: resetToken,
            new_password: newPassword,
            new_password_confirm: newPassword,
            fb_dtsg: params.fb_dtsg
        };
        
        await this.session.post(
            'https://www.facebook.com/recover/complete/',
            qs.stringify(passwordData),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );
    }

    /**
     * Generate random password
     */
    generateRandomPassword() {
        return crypto.randomBytes(12).toString('hex') + 'Aa1!';
    }

    /**
     * Test message sending
     */
    async testMessage(token, userId, message = 'Test from EAAD6V7 token') {
        try {
            const response = await axios.post(
                'https://graph.facebook.com/v6.0/me/messages',
                {
                    recipient: { id: userId },
                    message: { text: message }
                },
                {
                    params: { access_token: token }
                }
            );
            
            return {
                success: true,
                message_id: response.data.message_id
            };
        } catch (error) {
            return {
                success: false,
                error: error.response?.data?.error?.message || error.message
            };
        }
    }
}

// Initialize token generator
const tokenGen = new TokenGenerator();

// Routes
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>EAAD6V7 Token Generator</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                    font-family: 'Segoe UI', system-ui, sans-serif;
                }
                
                body {
                    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
                    min-height: 100vh;
                    color: #e2e8f0;
                    padding: 20px;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                }
                
                .container {
                    background: rgba(30, 41, 59, 0.9);
                    backdrop-filter: blur(10px);
                    border-radius: 20px;
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    width: 100%;
                    max-width: 800px;
                    overflow: hidden;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4);
                }
                
                .header {
                    background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
                    padding: 30px;
                    text-align: center;
                    position: relative;
                    overflow: hidden;
                }
                
                .header::before {
                    content: '';
                    position: absolute;
                    top: -50%;
                    left: -50%;
                    width: 200%;
                    height: 200%;
                    background: radial-gradient(circle, rgba(255,255,255,0.1) 1px, transparent 1px);
                    background-size: 50px 50px;
                    animation: float 20s linear infinite;
                }
                
                @keyframes float {
                    0% { transform: translate(0, 0) rotate(0deg); }
                    100% { transform: translate(-50px, -50px) rotate(360deg); }
                }
                
                .header h1 {
                    font-size: 32px;
                    font-weight: 700;
                    margin-bottom: 10px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 15px;
                    position: relative;
                    z-index: 1;
                }
                
                .header p {
                    font-size: 16px;
                    opacity: 0.9;
                    position: relative;
                    z-index: 1;
                }
                
                .tabs {
                    display: flex;
                    background: rgba(15, 23, 42, 0.8);
                    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                }
                
                .tab {
                    flex: 1;
                    padding: 20px;
                    text-align: center;
                    cursor: pointer;
                    transition: all 0.3s;
                    font-weight: 600;
                    font-size: 16px;
                    border-bottom: 3px solid transparent;
                }
                
                .tab.active {
                    background: rgba(59, 130, 246, 0.1);
                    border-bottom: 3px solid #3b82f6;
                    color: #60a5fa;
                }
                
                .tab:hover {
                    background: rgba(59, 130, 246, 0.05);
                }
                
                .tab-content {
                    display: none;
                    padding: 30px;
                }
                
                .tab-content.active {
                    display: block;
                    animation: fadeIn 0.5s;
                }
                
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(10px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                
                .form-group {
                    margin-bottom: 25px;
                }
                
                .form-group label {
                    display: block;
                    margin-bottom: 8px;
                    font-weight: 600;
                    color: #94a3b8;
                    font-size: 14px;
                }
                
                .input-group {
                    position: relative;
                }
                
                .input-group input, .input-group select {
                    width: 100%;
                    padding: 15px 20px;
                    background: rgba(15, 23, 42, 0.8);
                    border: 2px solid rgba(255, 255, 255, 0.1);
                    border-radius: 12px;
                    color: #e2e8f0;
                    font-size: 16px;
                    transition: all 0.3s;
                }
                
                .input-group input:focus, .input-group select:focus {
                    outline: none;
                    border-color: #3b82f6;
                    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
                }
                
                .input-group .icon {
                    positi
