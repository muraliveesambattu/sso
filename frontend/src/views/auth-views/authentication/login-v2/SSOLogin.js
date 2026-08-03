import { Button, Input, message, Divider } from 'antd';
import PropTypes from 'prop-types';
import { useState } from 'react'

const SCREEN = {
    INITIAL: 'INITIAL',
    SSO_EMAIL: 'SSO_EMAIL',
    SSO_DOMAIN: 'SSO_DOMAIN',
}

// ── Shared styles ────────────────────────────────────────────────────────────
const labelStyle = {
    fontSize: 13,
    fontWeight: 500,
    color: '#1a1a2e',
    marginBottom: 2,
}
const inputStyle = {
    height: 38,
    borderRadius: 6,
}
const primaryBtnStyle = {
    height: 42,
    borderRadius: 6,
    fontWeight: 500,
    fontSize: 14,
}
const zebraBtnStyle = {
    height: 42,
    borderRadius: 6,
    fontWeight: 500,
    fontSize: 14,
    borderColor: '#3e82f7',
    color: '#3e82f7',
}

// Public email domains — org domain input becomes mandatory for these
const PUBLIC_DOMAINS = new Set([
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
    'live.com', 'icloud.com', 'aol.com', 'protonmail.com',
    'mail.com', 'yandex.com', 'zoho.com', 'gmx.com',
])

const isPublicDomain = (email) => {
    const parts = email.trim().toLowerCase().split('@')
    if (parts.length !== 2) return false
    return PUBLIC_DOMAINS.has(parts[1])
}

const extractDomain = (email) => {
    const parts = email.trim().toLowerCase().split('@')
    return parts.length === 2 ? parts[1] : null
}

const buildOidcAuthorizeUrl = (config) => {
    const params = new URLSearchParams({
        client_id: config.client_id,
        response_type: 'code',
        redirect_uri: config.redirect_uri,
        scope: config.scope,
        state: config.state,
        nonce: config.nonce,
        response_mode: config.response_mode || 'query',
    })
    if (config.code_challenge) {
        params.set('code_challenge', config.code_challenge)
        params.set('code_challenge_method', config.code_challenge_method)
    }
    if (config.login_hint) {
        params.set('login_hint', config.login_hint)
    }
    return `${config.sso_url}?${params.toString()}`
}

const triggerSSORedirect = (payload, loginHint) => {
    if (payload.protocol === 'saml') {
        window.location.href = payload.redirectUrl
        return
    }
    if (payload.protocol === 'oidc') {
        localStorage.setItem('oidc_company_id', payload.company_id)
        const config = loginHint
            ? { ...payload.config, login_hint: loginHint }
            : payload.config
        window.location.href = buildOidcAuthorizeUrl(config)
    }
}

const fetchSSOConfig = async (payload) => {
    const MICROSERVICE_API_URL = process.env.REACT_APP_MICROSERVICE_API_URL
    let response
    try {
        response = await fetch(`${MICROSERVICE_API_URL}auth/domain-check`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        })
    } catch {
        const err = new Error('Unable to reach the server. Please check your connection.')
        err.code = 'NETWORK_ERROR'
        throw err
    }
    let data
    try {
        data = await response.json()
    } catch {
        const err = new Error('Invalid response from server.')
        err.code = 'PARSE_ERROR'
        throw err
    }
    if (!response.ok) {
        const err = new Error(data.error?.message || 'Request failed')
        err.statusCode = response.status
        err.code = data.error?.code
        throw err
    }
    return data
}

const getErrorMessage = (err) => {
    switch (err.statusCode) {
        case 400: return 'Invalid input. Please check your email or domain.'
        case 401: return 'Authentication failed. Please try again.'
        case 404: return 'SSO not configured for this email or domain.'
        case 429: return 'Too many attempts. Please wait and try again.'
        case 500: return 'Server error. Please try again later.'
        default:  return err.message || 'Something went wrong. Please try again.'
    }
}

export const SSOLogin = ({ onScreenChange, onZebraLogin }) => {
    const [screen, setScreen]       = useState(SCREEN.SSO_EMAIL)
    const [ssoEmail, setSSOEmail]   = useState('')
    const [orgDomain, setOrgDomain] = useState('')
    const [loading, setLoading]     = useState(false)

    const changeScreen = (s) => {
        setScreen(s)
        onScreenChange?.(s)
    }

    const handleEmailContinue = async () => {
        if (!ssoEmail.trim()) {
            message.error('Please enter your email address.')
            return
        }
        const emailIsPublic   = isPublicDomain(ssoEmail)
        const extractedDomain = extractDomain(ssoEmail)

        if (emailIsPublic && orgDomain.trim()) {
            await runDomainCheck(orgDomain.trim().toLowerCase(), ssoEmail.trim())
            return
        }
        if (emailIsPublic && !orgDomain.trim()) {
            message.error('Please enter your Organization Domain for public email addresses.')
            return
        }
        if (!emailIsPublic && orgDomain.trim()) {
            await runDomainCheck(orgDomain.trim().toLowerCase(), ssoEmail.trim())
            return
        }
        await runDomainCheck(extractedDomain, ssoEmail.trim())
    }

    const runDomainCheck = async (domain, loginHint) => {
        setLoading(true)
        try {
            const data = await fetchSSOConfig({ domain })
            if (data.found) {
                triggerSSORedirect(data, loginHint)
            } else if (data.promptOrgDomain) {
                changeScreen(SCREEN.SSO_DOMAIN)
            } else {
                message.error('SSO is not available for your organization. Please contact your administrator.')
            }
        } catch (err) {
            message.error(err.code === 'NETWORK_ERROR' ? err.message : getErrorMessage(err))
        } finally {
            setLoading(false)
        }
    }

    const handleDomainContinue = async () => {
        if (!orgDomain.trim()) {
            message.error('Please enter your organization domain.')
            return
        }
        setLoading(true)
        try {
            const data = await fetchSSOConfig({ domain: orgDomain.trim().toLowerCase() })
            if (data.found) {
                triggerSSORedirect(data, ssoEmail.trim() || null)
            } else {
                message.error('SSO is not available for your organization. Please contact your administrator.')
            }
        } catch (err) {
            message.error(err.code === 'NETWORK_ERROR' ? err.message : getErrorMessage(err))
        } finally {
            setLoading(false)
        }
    }

    if (screen === SCREEN.SSO_EMAIL) {
        const emailIsPublic = ssoEmail.trim() ? isPublicDomain(ssoEmail) : false
        return (
            <div id="sso-email-screen" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <div id="work-email-label" style={labelStyle}>Work Email Address*</div>
                <Input
                    id='EntraSSOEmail-input'
                    type="email"
                    placeholder="Enter your work email"
                    value={ssoEmail}
                    onChange={(e) => setSSOEmail(e.target.value)}
                    onPressEnter={handleEmailContinue}
                    style={inputStyle}
                />
                <div id="org-domain-label" style={labelStyle}>
                    Organization Domain
                    {emailIsPublic                                                               // fix: negated condition -> ternary (S7735)
                        ? <span id="org-domain-required" style={{ color: '#ff4d4f' }}> *</span>
                        : <span id="org-domain-optional" style={{ color: '#9ca3af', fontSize: 12 }}> (optional)</span>
                    }
                </div>
                <Input
                    id='emailDomain-input'
                    type="text"
                    placeholder="e.g. contoso.com"
                    value={orgDomain}
                    onChange={(e) => setOrgDomain(e.target.value)}
                    onPressEnter={handleEmailContinue}
                    style={inputStyle}
                />
                <Button
                    id='SSO-continue-1'
                    type="primary"
                    block
                    loading={loading}
                    onClick={handleEmailContinue}
                    style={primaryBtnStyle}
                >
                    Continue
                </Button>
                <Divider id="sso-or-divider-1">or</Divider>
                <Button
                    id='zebra-login-btn'
                    block
                    onClick={onZebraLogin}
                    style={zebraBtnStyle}
                >
                    Continue with Zebra Account
                </Button>
            </div>
        )
    }

    if (screen === SCREEN.SSO_DOMAIN) {
        return (
            <div id="sso-org-domain-screen" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <div id="work-email-label-screen2" style={labelStyle}>Work Email Address*</div>
                <Input
                    id='EntraSSOEmail-input-2'
                    type="email"
                    value={ssoEmail}
                    disabled
                    style={{ ...inputStyle, background: '#f5f5f5' }}
                />
                <div id="org-domain-input-box" style={{
                    border: '2px solid #E8A000',
                    borderRadius: 8,
                    padding: 12,
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 8,
                }}>
                    <div id="org-domain-label-screen2" style={labelStyle}>Organization Domain*</div>
                    <Input
                        id='emailDomain-input-2'
                        type="text"
                        placeholder="e.g. contoso.com"
                        value={orgDomain}
                        onChange={(e) => setOrgDomain(e.target.value)}
                        onPressEnter={handleDomainContinue}
                        style={inputStyle}
                    />
                    <Button
                        id='SSO-continue-2'
                        type="primary"
                        block
                        loading={loading}
                        onClick={handleDomainContinue}
                        style={primaryBtnStyle}
                    >
                        Continue
                    </Button>
                </div>
                <Divider id="sso-or-divider-2">or</Divider>
                <Button
                    id='zebra-login-btn-1'
                    block
                    onClick={onZebraLogin}
                    style={zebraBtnStyle}
                >
                    Continue with Zebra Account
                </Button>
            </div>
        )
    }
}

SSOLogin.propTypes = {
    onScreenChange: PropTypes.func,
    onZebraLogin: PropTypes.func,
}
