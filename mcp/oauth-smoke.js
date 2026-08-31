#!/usr/bin/env node
'use strict';

const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const https = require('https');

const ORIGIN = process.env.GOMCP_PUBLIC_ORIGIN || 'https://8.235.7.248';
const OWNER_KEY_FILE = process.env.GOMCP_OWNER_KEY_FILE || 'C:\\actions-runner\\GoMCP\\state\\mcp.token';
const RESOURCE = `${ORIGIN}/goproxy/mcp`;
const PRM = `${ORIGIN}/.well-known/oauth-protected-resource/goproxy/mcp`;
const AS_META = `${ORIGIN}/.well-known/oauth-authorization-server/goproxy/oauth`;
const CALLBACK = 'https://chatgpt.com/connector/oauth/gomcp-deployment-smoke';

function assert(value, message) {
  if (!value) throw new Error(message);
}

function request(url, options = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const transport = u.protocol === 'https:' ? https : http;
    const body = options.body == null ? null : Buffer.from(options.body);
    const headers = { ...(options.headers || {}) };
    if (body && headers['Content-Length'] == null) headers['Content-Length'] = String(body.length);
    const req = transport.request(u, {
      method: options.method || 'GET',
      headers,
      timeout: options.timeoutMs || 20000,
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('timeout', () => req.destroy(new Error(`timeout requesting ${u.origin}${u.pathname}`)));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function json(text, label) {
  try { return JSON.parse(text); }
  catch { throw new Error(`${label} did not return JSON`); }
}

function form(data) {
  return new URLSearchParams(data).toString();
}

async function main() {
  const ownerKey = fs.readFileSync(OWNER_KEY_FILE, 'utf8').trim();
  assert(ownerKey.length >= 32, 'owner key is missing or too short');

  const prmResponse = await request(PRM);
  assert(prmResponse.status === 200, `protected resource metadata status=${prmResponse.status}`);
  const prm = json(prmResponse.body, 'protected resource metadata');
  assert(prm.resource === RESOURCE, 'protected resource metadata resource mismatch');
  assert(Array.isArray(prm.authorization_servers) && prm.authorization_servers.length === 1, 'authorization server discovery missing');
  const issuer = prm.authorization_servers[0];

  const metaResponse = await request(AS_META);
  assert(metaResponse.status === 200, `authorization metadata status=${metaResponse.status}`);
  const meta = json(metaResponse.body, 'authorization metadata');
  assert(meta.issuer === issuer, 'issuer mismatch');
  assert(meta.registration_endpoint, 'DCR registration endpoint missing');
  assert(meta.authorization_endpoint, 'authorization endpoint missing');
  assert(meta.token_endpoint, 'token endpoint missing');
  assert((meta.code_challenge_methods_supported || []).includes('S256'), 'PKCE S256 not advertised');
  assert((meta.grant_types_supported || []).includes('refresh_token'), 'refresh token grant not advertised');
  assert((meta.scopes_supported || []).includes('offline_access'), 'offline_access not advertised');

  const unauthBody = JSON.stringify({ jsonrpc: '2.0', id: 10, method: 'ping', params: {} });
  const unauth = await request(RESOURCE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: unauthBody,
  });
  assert(unauth.status === 401, `unauthenticated MCP expected 401, got ${unauth.status}`);
  assert(String(unauth.headers['www-authenticate'] || '').includes('resource_metadata='), 'OAuth resource_metadata challenge missing');

  const registration = await request(meta.registration_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_name: 'GoMCP deployment smoke test',
      redirect_uris: [CALLBACK],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      application_type: 'web',
    }),
  });
  assert(registration.status === 201, `DCR expected 201, got ${registration.status}: ${registration.body}`);
  const client = json(registration.body, 'DCR response');
  assert(client.client_id, 'DCR client_id missing');

  const verifier = crypto.randomBytes(48).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier, 'ascii').digest('base64url');
  const state = crypto.randomBytes(18).toString('base64url');
  const authorizeUrl = new URL(meta.authorization_endpoint);
  authorizeUrl.search = new URLSearchParams({
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: CALLBACK,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
    scope: 'gomcp offline_access',
    resource: RESOURCE,
  }).toString();

  const authorizePage = await request(authorizeUrl);
  assert(authorizePage.status === 200, `authorize page expected 200, got ${authorizePage.status}`);
  const match = authorizePage.body.match(/name="request_id" value="([^"]+)"/);
  assert(match, 'authorization request_id was not rendered');
  const requestId = match[1];

  const approval = await request(meta.authorization_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form({ request_id: requestId, access_key: ownerKey }),
  });
  assert(approval.status === 302, `owner approval expected 302, got ${approval.status}: ${approval.body}`);
  const location = approval.headers.location;
  assert(location, 'authorization redirect location missing');
  const callback = new URL(location);
  assert(callback.origin === 'https://chatgpt.com', 'authorization redirected outside chatgpt.com');
  assert(callback.searchParams.get('state') === state, 'OAuth state mismatch');
  assert(callback.searchParams.get('iss') === issuer, 'OAuth iss mismatch');
  const code = callback.searchParams.get('code');
  assert(code, 'authorization code missing');

  const tokenResponse = await request(meta.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form({
      grant_type: 'authorization_code',
      client_id: client.client_id,
      code,
      redirect_uri: CALLBACK,
      code_verifier: verifier,
      resource: RESOURCE,
    }),
  });
  assert(tokenResponse.status === 200, `token exchange expected 200, got ${tokenResponse.status}: ${tokenResponse.body}`);
  const tokens = json(tokenResponse.body, 'token response');
  assert(tokens.access_token, 'access_token missing');
  assert(tokens.refresh_token, 'refresh_token missing');
  assert(String(tokens.scope || '').includes('offline_access'), 'offline_access grant missing');

  const listBody = JSON.stringify({ jsonrpc: '2.0', id: 11, method: 'tools/list', params: {} });
  const toolList = await request(RESOURCE, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${tokens.access_token}`,
      'Content-Type': 'application/json',
    },
    body: listBody,
  });
  assert(toolList.status === 200, `OAuth tools/list expected 200, got ${toolList.status}: ${toolList.body}`);
  const listRpc = json(toolList.body, 'tools/list');
  assert(listRpc.result && Array.isArray(listRpc.result.tools), 'tools/list result missing');
  assert(listRpc.result.tools.length === 50, `expected 50 tools, got ${listRpc.result.tools.length}`);

  const refreshResponse = await request(meta.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form({
      grant_type: 'refresh_token',
      client_id: client.client_id,
      refresh_token: tokens.refresh_token,
      resource: RESOURCE,
    }),
  });
  assert(refreshResponse.status === 200, `refresh expected 200, got ${refreshResponse.status}: ${refreshResponse.body}`);
  const refreshed = json(refreshResponse.body, 'refresh response');
  assert(refreshed.access_token && refreshed.refresh_token, 'rotated refresh credentials missing');
  assert(refreshed.refresh_token !== tokens.refresh_token, 'refresh token was not rotated');

  const pingBody = JSON.stringify({ jsonrpc: '2.0', id: 12, method: 'ping', params: {} });
  const ping = await request(RESOURCE, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${refreshed.access_token}`,
      'Content-Type': 'application/json',
    },
    body: pingBody,
  });
  assert(ping.status === 200, `refreshed-token ping expected 200, got ${ping.status}: ${ping.body}`);
  const pingRpc = json(ping.body, 'refresh ping');
  assert(pingRpc.jsonrpc === '2.0' && pingRpc.id === 12 && pingRpc.result, 'refreshed-token ping response invalid');

  console.log('oauth_smoke=success tools=50 refresh=success dcr=success pkce=S256');
}

main().catch(err => {
  console.error(`oauth_smoke=failed ${err.message}`);
  process.exit(1);
});
