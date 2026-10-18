'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function jsonResponse(res, status, payload, headers = {}) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(body);
}

function readBody(req, max = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];
    req.on('data', chunk => {
      total += chunk.length;
      if (total > max) {
        reject(new Error('request too large'));
        try { req.destroy(); } catch {}
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function htmlEscape(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, ch => ({
    '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'
  }[ch]));
}

function sendHtml(res, status, html) {
  const body = Buffer.from(html, 'utf8');
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
  });
  res.end(body);
}

function ensureSecret(file, bytes) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (!fs.existsSync(file) || !fs.readFileSync(file, 'utf8').trim()) {
    fs.writeFileSync(file, crypto.randomBytes(bytes).toString('base64url') + '\n', { encoding:'utf8', mode:0o600 });
  }
  return fs.readFileSync(file, 'utf8').trim();
}

function createOAuth(options) {
  const stateDir = options.stateDir;
  const publicBase = String(options.publicBase).replace(/\/+$/, '');
  const staticToken = String(options.staticToken || '');
  const scopeName = 'gomcp:full';
  const stateFile = path.join(stateDir, 'oauth-state.json');
  const ownerKeyFile = path.join(stateDir, 'owner.key');
  const logFile = path.join(stateDir, 'oauth.log');
  const ownerKey = ensureSecret(ownerKeyFile, 24);
  const accessTtl = 60 * 60 * 1000;
  const refreshTtl = 30 * 24 * 60 * 60 * 1000;
  const codeTtl = 5 * 60 * 1000;

  const accessTokens = new Map();
  const refreshTokens = new Map();
  const authCodes = new Map();
  const clients = new Map();

  function digest(value) {
    return crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex');
  }

  function resource() {
    return publicBase + '/mcp';
  }

  function authToken(req) {
    const raw = String(req.headers.authorization || '');
    if (/^Bearer\s+/i.test(raw)) return raw.replace(/^Bearer\s+/i, '').trim();
    return String(req.headers['x-gomcp-token'] || '').trim();
  }

  function log(event, data) {
    try {
      fs.mkdirSync(path.dirname(logFile), { recursive:true });
      fs.appendFileSync(logFile, JSON.stringify({ ts:new Date().toISOString(), event, ...(data || {}) }) + '\n', 'utf8');
    } catch {}
  }

  function persist() {
    fs.mkdirSync(path.dirname(stateFile), { recursive:true });
    fs.writeFileSync(stateFile, JSON.stringify({
      accessTokens:[...accessTokens.entries()],
      refreshTokens:[...refreshTokens.entries()],
      clients:[...clients.entries()],
    }, null, 2) + '\n', { encoding:'utf8', mode:0o600 });
  }

  function restore() {
    try {
      const state = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
      const now = Date.now();
      for (const [key, grant] of state.accessTokens || []) {
        if (grant && grant.expiresAt > now) accessTokens.set(key, grant);
      }
      for (const [key, grant] of state.refreshTokens || []) {
        if (grant && grant.expiresAt > now) refreshTokens.set(key, grant);
      }
      for (const [id, client] of state.clients || []) {
        if (id && client) clients.set(id, client);
      }
    } catch (err) {
      if (!err || err.code !== 'ENOENT') console.warn('[oauth] restore skipped:', err && err.message ? err.message : err);
    }
  }
  restore();

  function authorized(req) {
    const token = authToken(req);
    if (staticToken && safeEqual(token, staticToken)) return true;
    if (!token) return false;
    const key = digest(token);
    const grant = accessTokens.get(key);
    if (!grant) return false;
    if (grant.expiresAt <= Date.now()) {
      accessTokens.delete(key);
      persist();
      return false;
    }
    return grant.resource === resource() && clients.has(grant.clientId);
  }

  function challenge() {
    return 'Bearer realm="GoMCP", resource_metadata="' +
      publicBase + '/.well-known/oauth-protected-resource/mcp", scope="' + scopeName + '"';
  }

  function protectedResourceMetadata() {
    return {
      resource: resource(),
      resource_name: 'GoMCP GamePC',
      authorization_servers: [publicBase],
      bearer_methods_supported: ['header'],
      scopes_supported: [scopeName],
    };
  }

  function authorizationServerMetadata() {
    return {
      issuer: publicBase,
      authorization_endpoint: publicBase + '/authorize',
      token_endpoint: publicBase + '/token',
      registration_endpoint: publicBase + '/register',
      scopes_supported: [scopeName],
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
      code_challenge_methods_supported: ['S256'],
    };
  }

  function validateRedirect(client, redirectUri) {
    return Boolean(client && Array.isArray(client.redirectUris) && client.redirectUris.includes(redirectUri));
  }

  function validateAuthorize(params) {
    if (params.get('response_type') !== 'code') return 'unsupported_response_type';
    const client = clients.get(params.get('client_id') || '');
    if (!client) return 'unauthorized_client';
    const redirectUri = params.get('redirect_uri') || '';
    if (!validateRedirect(client, redirectUri)) return 'invalid_request';
    const scopes = String(params.get('scope') || scopeName).split(/\s+/).filter(Boolean);
    if (!scopes.includes(scopeName)) return 'invalid_scope';
    if ((params.get('resource') || resource()) !== resource()) return 'invalid_target';
    if (!(params.get('code_challenge') || '') || (params.get('code_challenge_method') || '') !== 'S256') {
      return 'invalid_request';
    }
    return null;
  }

  function redirectError(res, redirectUri, state, error) {
    const u = new URL(redirectUri);
    u.searchParams.set('error', error);
    if (state) u.searchParams.set('state', state);
    res.writeHead(302, { Location:u.toString(), 'Cache-Control':'no-store' });
    res.end();
  }

  async function register(req, res) {
    if (req.method !== 'POST') return jsonResponse(res, 405, { error:'method_not_allowed' }, { Allow:'POST' });
    let input;
    try { input = JSON.parse((await readBody(req)).toString('utf8')); }
    catch { return jsonResponse(res, 400, { error:'invalid_client_metadata' }); }

    const redirectUris = Array.isArray(input.redirect_uris) ? input.redirect_uris.map(String) : [];
    if (!redirectUris.length) return jsonResponse(res, 400, { error:'invalid_redirect_uri' });
    for (const uri of redirectUris) {
      let u;
      try { u = new URL(uri); } catch { return jsonResponse(res, 400, { error:'invalid_redirect_uri' }); }
      if (!['https:','http:'].includes(u.protocol)) return jsonResponse(res, 400, { error:'invalid_redirect_uri' });
      if (u.protocol === 'http:' && !['127.0.0.1','localhost','[::1]'].includes(u.hostname)) {
        return jsonResponse(res, 400, { error:'invalid_redirect_uri' });
      }
    }

    const method = String(input.token_endpoint_auth_method || 'none');
    if (!['none','client_secret_post','client_secret_basic'].includes(method)) {
      return jsonResponse(res, 400, { error:'invalid_client_metadata' });
    }

    const clientId = 'gomcp-' + crypto.randomBytes(18).toString('base64url');
    const clientSecret = method === 'none' ? '' : crypto.randomBytes(36).toString('base64url');
    clients.set(clientId, {
      clientId,
      clientSecret,
      tokenEndpointAuthMethod: method,
      redirectUris,
      clientName: String(input.client_name || 'Dynamic MCP client').slice(0, 200),
      createdAt: Date.now(),
    });
    persist();
    log('client_registered', { clientId, method, redirectCount:redirectUris.length });

    const out = {
      client_id: clientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      redirect_uris: redirectUris,
      token_endpoint_auth_method: method,
      grant_types: ['authorization_code','refresh_token'],
      response_types: ['code'],
    };
    if (clientSecret) {
      out.client_secret = clientSecret;
      out.client_secret_expires_at = 0;
    }
    return jsonResponse(res, 201, out, { 'Access-Control-Allow-Origin':'*' });
  }

  function authorizePage(params, errorText) {
    const names = ['response_type','client_id','redirect_uri','scope','state','resource','code_challenge','code_challenge_method'];
    const hidden = names.map(name =>
      '<input type="hidden" name="' + name + '" value="' + htmlEscape(params.get(name) || '') + '">'
    ).join('\n');
    const client = clients.get(params.get('client_id') || '');
    const clientName = client ? client.clientName : 'Unknown client';
    const error = errorText ? '<p class="err">' + htmlEscape(errorText) + '</p>' : '';
    return '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<title>Authorize GoMCP</title><style>' +
      'body{font-family:Segoe UI,Arial,sans-serif;background:#111;color:#eee;max-width:680px;margin:40px auto;padding:24px}' +
      '.card{background:#1b1b1b;border:1px solid #444;border-radius:14px;padding:24px}' +
      'h1{margin-top:0}.muted{color:#aaa}.err{color:#ff8d8d;font-weight:700}' +
      'input[type=password]{width:100%;box-sizing:border-box;font-size:20px;padding:12px;margin:10px 0 16px;background:#0d0d0d;color:#fff;border:1px solid #666;border-radius:8px}' +
      'button{font-size:18px;padding:12px 18px;border:0;border-radius:8px;cursor:pointer}' +
      '</style></head><body><div class="card"><h1>Authorize GoMCP</h1>' +
      '<p><b>' + htmlEscape(clientName) + '</b> is requesting <code>' + scopeName + '</code> access to GamePC.</p>' +
      '<p class="muted">Enter the owner key generated by the GoMCP installer.</p>' + error +
      '<form method="post" action="/authorize">' + hidden +
      '<label>Owner key</label><input name="owner_key" type="password" autocomplete="off" autofocus required>' +
      '<button type="submit">Authorize</button></form></div></body></html>';
  }

  async function authorize(req, res, requestUrl) {
    if (req.method === 'GET') {
      const error = validateAuthorize(requestUrl.searchParams);
      if (error) {
        const client = clients.get(requestUrl.searchParams.get('client_id') || '');
        const redirectUri = requestUrl.searchParams.get('redirect_uri') || '';
        const state = requestUrl.searchParams.get('state') || '';
        if (redirectUri && validateRedirect(client, redirectUri)) return redirectError(res, redirectUri, state, error);
        return sendHtml(res, 400, authorizePage(requestUrl.searchParams, error));
      }
      return sendHtml(res, 200, authorizePage(requestUrl.searchParams, ''));
    }

    if (req.method !== 'POST') return jsonResponse(res, 405, { error:'method_not_allowed' }, { Allow:'GET, POST' });
    const params = new URLSearchParams((await readBody(req)).toString('utf8'));
    const error = validateAuthorize(params);
    const client = clients.get(params.get('client_id') || '');
    const redirectUri = params.get('redirect_uri') || '';
    const state = params.get('state') || '';
    if (error) {
      if (redirectUri && validateRedirect(client, redirectUri)) return redirectError(res, redirectUri, state, error);
      return sendHtml(res, 400, authorizePage(params, error));
    }

    if (!safeEqual(params.get('owner_key') || '', ownerKey)) {
      log('authorize_rejected', { clientId:params.get('client_id') || '', reason:'bad_owner_key' });
      return sendHtml(res, 403, authorizePage(params, 'Owner key did not match.'));
    }

    const code = crypto.randomBytes(32).toString('base64url');
    authCodes.set(digest(code), {
      clientId: params.get('client_id'),
      redirectUri,
      scope: params.get('scope') || scopeName,
      resource: params.get('resource') || resource(),
      codeChallenge: params.get('code_challenge') || '',
      expiresAt: Date.now() + codeTtl,
    });
    log('authorize_approved', { clientId:params.get('client_id') || '' });

    const u = new URL(redirectUri);
    u.searchParams.set('code', code);
    if (state) u.searchParams.set('state', state);
    res.writeHead(302, { Location:u.toString(), 'Cache-Control':'no-store' });
    res.end();
  }

  function clientCredentials(req, params) {
    let clientId = params.get('client_id') || '';
    let clientSecret = params.get('client_secret') || '';
    const match = String(req.headers.authorization || '').match(/^Basic\s+(.+)$/i);
    if (match) {
      try {
        const raw = Buffer.from(match[1], 'base64').toString('utf8');
        const split = raw.indexOf(':');
        clientId = decodeURIComponent(split >= 0 ? raw.slice(0, split) : raw);
        clientSecret = decodeURIComponent(split >= 0 ? raw.slice(split + 1) : '');
      } catch {}
    }
    return { clientId, clientSecret };
  }

  function authenticateClient(req, params) {
    const creds = clientCredentials(req, params);
    const client = clients.get(creds.clientId);
    if (!client) return null;
    if (client.tokenEndpointAuthMethod === 'none') return client;
    if (!client.clientSecret || !safeEqual(client.clientSecret, creds.clientSecret)) return null;
    return client;
  }

  function issueTokens(clientId, scope, targetResource) {
    const accessToken = crypto.randomBytes(48).toString('base64url');
    const refreshToken = crypto.randomBytes(48).toString('base64url');
    const now = Date.now();
    accessTokens.set(digest(accessToken), { clientId, scope, resource:targetResource, expiresAt:now + accessTtl });
    refreshTokens.set(digest(refreshToken), { clientId, scope, resource:targetResource, expiresAt:now + refreshTtl });
    persist();
    return { accessToken, refreshToken };
  }

  async function token(req, res) {
    if (req.method !== 'POST') return jsonResponse(res, 405, { error:'method_not_allowed' }, { Allow:'POST' });
    const params = new URLSearchParams((await readBody(req)).toString('utf8'));
    const grantType = params.get('grant_type') || '';
    const client = authenticateClient(req, params);
    if (!client) return jsonResponse(res, 401, { error:'invalid_client' });

    if (grantType === 'authorization_code') {
      const key = digest(params.get('code') || '');
      const grant = authCodes.get(key);
      authCodes.delete(key);
      if (!grant || grant.expiresAt <= Date.now() || grant.clientId !== client.clientId) {
        return jsonResponse(res, 400, { error:'invalid_grant' });
      }
      if ((params.get('redirect_uri') || '') !== grant.redirectUri) {
        return jsonResponse(res, 400, { error:'invalid_grant' });
      }
      const verifier = params.get('code_verifier') || '';
      const computed = verifier ? crypto.createHash('sha256').update(verifier).digest('base64url') : '';
      if (!verifier || !safeEqual(computed, grant.codeChallenge)) {
        log('token_rejected', { reason:'invalid_code_verifier', clientId:client.clientId });
        return jsonResponse(res, 400, { error:'invalid_grant' });
      }
      const issued = issueTokens(client.clientId, grant.scope, grant.resource);
      return jsonResponse(res, 200, {
        access_token:issued.accessToken,
        token_type:'Bearer',
        expires_in:Math.floor(accessTtl / 1000),
        refresh_token:issued.refreshToken,
        scope:grant.scope,
      });
    }

    if (grantType === 'refresh_token') {
      const key = digest(params.get('refresh_token') || '');
      const grant = refreshTokens.get(key);
      refreshTokens.delete(key);
      if (!grant || grant.expiresAt <= Date.now() || grant.clientId !== client.clientId) {
        persist();
        return jsonResponse(res, 400, { error:'invalid_grant' });
      }
      const issued = issueTokens(client.clientId, grant.scope, grant.resource);
      return jsonResponse(res, 200, {
        access_token:issued.accessToken,
        token_type:'Bearer',
        expires_in:Math.floor(accessTtl / 1000),
        refresh_token:issued.refreshToken,
        scope:grant.scope,
      });
    }

    return jsonResponse(res, 400, { error:'unsupported_grant_type' });
  }

  return {
    authorized,
    challenge,
    protectedResourceMetadata,
    authorizationServerMetadata,
    register,
    authorize,
    token,
    ownerKeyFile,
  };
}

module.exports = { createOAuth };
