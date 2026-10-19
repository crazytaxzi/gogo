#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const sourceDir = __dirname;
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'gomcp-selftest-'));
const home = path.join(temp, 'home');
const state = path.join(home, 'state');
const drive = path.join(temp, 'drive');
const remoteFile = path.join(home, 'remote-targets.json');
const port = 18882 + Math.floor(Math.random() * 500);
const base = 'http://127.0.0.1:' + port;

fs.mkdirSync(state, { recursive:true });
fs.mkdirSync(drive, { recursive:true });
fs.writeFileSync(remoteFile, JSON.stringify({ targets:[] }, null, 2));

const child = spawn(process.execPath, [path.join(sourceDir, 'gomcp.js')], {
  cwd: sourceDir,
  env: {
    ...process.env,
    GOMCP_HOME: home,
    GOMCP_STATE: state,
    GOMCP_PORT: String(port),
    GOMCP_PUBLIC_BASE: base,
    GOMCP_DRIVE_ROOT: drive,
    GOMCP_REMOTE_TARGETS: remoteFile,
    SENTIONCE_MUTATION_FIREWALL_MODE: 'required',
    SENTIONCE_MUTATION_FIREWALL_EXE: 'E:\\SentionceRecovery\\MutationFirewall\\publish\\SentionceMutationFirewall.exe',
    SENTIONCE_MUTATION_FIREWALL_POLICY: 'E:\\SentionceRecovery\\MutationFirewall\\policy.json',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});

let output = '';
child.stdout.on('data', c => { output += c.toString(); process.stdout.write(c); });
child.stderr.on('data', c => { output += c.toString(); process.stderr.write(c); });

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function assert(ok, message) { if (!ok) throw new Error(message); }
function b64urlSha256(value) {
  return crypto.createHash('sha256').update(value).digest('base64url');
}

async function waitForHealth() {
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(base + '/health');
      if (r.ok) {
        const j = await r.json();
        if (j.ok) return j;
      }
    } catch {}
    await sleep(200);
  }
  throw new Error('GoMCP did not become healthy. Output:\n' + output);
}

async function main() {
  const health = await waitForHealth();
  assert(health.toolCount === 56, 'Expected 56 tools, got ' + health.toolCount);
  assert(health.oauth === true, 'Health did not advertise OAuth');

  const prm = await (await fetch(base + '/.well-known/oauth-protected-resource/mcp')).json();
  assert(prm.resource === base + '/mcp', 'Protected resource metadata mismatch');

  const asm = await (await fetch(base + '/.well-known/oauth-authorization-server')).json();
  assert(asm.registration_endpoint === base + '/register', 'DCR endpoint missing');
  assert(Array.isArray(asm.code_challenge_methods_supported) && asm.code_challenge_methods_supported.includes('S256'), 'PKCE S256 missing');

  const redirectUri = 'http://127.0.0.1/callback';
  const regResp = await fetch(base + '/register', {
    method:'POST',
    headers:{ 'content-type':'application/json' },
    body:JSON.stringify({
      client_name:'GoMCP self-test',
      redirect_uris:[redirectUri],
      token_endpoint_auth_method:'none',
      grant_types:['authorization_code','refresh_token'],
      response_types:['code'],
    }),
  });
  if (regResp.status !== 201) throw new Error('DCR failed HTTP ' + regResp.status + ': ' + await regResp.text());
  const client = await regResp.json();
  assert(client.client_id, 'DCR returned no client_id');

  const verifier = crypto.randomBytes(48).toString('base64url');
  const challenge = b64urlSha256(verifier);
  const stateValue = crypto.randomBytes(12).toString('hex');
  const authorizeParams = new URLSearchParams({
    response_type:'code',
    client_id:client.client_id,
    redirect_uri:redirectUri,
    scope:'gomcp:full',
    state:stateValue,
    resource:base + '/mcp',
    code_challenge:challenge,
    code_challenge_method:'S256',
  });

  const page = await fetch(base + '/authorize?' + authorizeParams.toString(), { redirect:'manual' });
  assert(page.status === 200, 'Authorize GET failed HTTP ' + page.status);

  const ownerKey = fs.readFileSync(path.join(state, 'owner.key'), 'utf8').trim();
  assert(ownerKey.length >= 20, 'Owner key not generated');

  const approve = new URLSearchParams(authorizeParams);
  approve.set('owner_key', ownerKey);
  const approved = await fetch(base + '/authorize', {
    method:'POST',
    redirect:'manual',
    headers:{ 'content-type':'application/x-www-form-urlencoded' },
    body:approve.toString(),
  });
  if (approved.status !== 302) throw new Error('Authorize POST failed HTTP ' + approved.status + ': ' + await approved.text());
  const location = approved.headers.get('location');
  assert(location, 'Authorize POST returned no redirect');
  const redirect = new URL(location);
  assert(redirect.searchParams.get('state') === stateValue, 'OAuth state mismatch');
  const code = redirect.searchParams.get('code');
  assert(code, 'No authorization code returned');

  const tokenBody = new URLSearchParams({
    grant_type:'authorization_code',
    code,
    client_id:client.client_id,
    redirect_uri:redirectUri,
    code_verifier:verifier,
  });
  const tokenResp = await fetch(base + '/token', {
    method:'POST',
    headers:{ 'content-type':'application/x-www-form-urlencoded' },
    body:tokenBody.toString(),
  });
  if (!tokenResp.ok) throw new Error('Token exchange failed HTTP ' + tokenResp.status + ': ' + await tokenResp.text());
  const tokens = await tokenResp.json();
  assert(tokens.access_token && tokens.refresh_token, 'Token response incomplete');

  const rpcResp = await fetch(base + '/mcp', {
    method:'POST',
    headers:{
      authorization:'Bearer ' + tokens.access_token,
      'content-type':'application/json',
      accept:'application/json',
      'mcp-protocol-version':'2026-07-28',
    },
    body:JSON.stringify({ jsonrpc:'2.0', id:1, method:'tools/list', params:{} }),
  });
  if (!rpcResp.ok) throw new Error('Authenticated MCP call failed HTTP ' + rpcResp.status + ': ' + await rpcResp.text());
  const rpc = await rpcResp.json();
  assert(rpc.result && Array.isArray(rpc.result.tools), 'tools/list returned no tools');
  assert(rpc.result.tools.length === 56, 'Authenticated tools/list expected 56, got ' + rpc.result.tools.length);

  const names = new Set(rpc.result.tools.map(t => t.name));
  for (const name of ['drive.list','drive.link','remote.targets','remote.health','remote.list_tools','remote.call']) {
    assert(names.has(name), 'Missing rebuilt tool ' + name);
  }

  let rpcId = 10;
  async function callTool(name, args) {
    const r = await fetch(base + '/mcp', {
      method:'POST',
      headers:{
        authorization:'Bearer ' + tokens.access_token,
        'content-type':'application/json',
        accept:'application/json',
        'mcp-protocol-version':'2026-07-28',
      },
      body:JSON.stringify({
        jsonrpc:'2.0',
        id:rpcId++,
        method:'tools/call',
        params:{ name, arguments:args || {} },
      }),
    });
    if (!r.ok) throw new Error('tools/call ' + name + ' failed HTTP ' + r.status + ': ' + await r.text());
    const body = await r.json();
    assert(body.result, 'tools/call ' + name + ' returned no result');
    return body.result;
  }

  const harmlessFormat = await callTool('shell.run', {
    shell:'powershell',
    command:"Write-Output '--format=csv,noheader'",
  });
  assert(harmlessFormat.isError !== true, 'harmless --format option was falsely blocked by Mutation Firewall');

  const overwriteGuardFile = path.join(temp, 'must-survive-overwrite.txt');
  fs.writeFileSync(overwriteGuardFile, 'original', 'utf8');
  const overwriteBlocked = await callTool('shell.run', {
    shell:'powershell',
    command:"Set-Content -LiteralPath '" + overwriteGuardFile.replace(/'/g, "''") + "' -Value 'replacement'",
  });
  assert(overwriteBlocked.isError === true, 'overwrite-capable shell command was not broker-gated');
  assert(
    overwriteBlocked.structuredContent &&
    /MUTATION_BROKER_REQUIRED/.test(String(overwriteBlocked.structuredContent.error || '')),
    'overwrite guard did not report MUTATION_BROKER_REQUIRED'
  );
  assert(fs.readFileSync(overwriteGuardFile, 'utf8') === 'original', 'overwrite guard failed to preserve original content');

  const protectedWritePath = path.join(path.parse(temp).root, 'Windows', 'System32', 'sentionce-mutation-firewall-should-not-exist.txt');
  const protectedWrite = await callTool('file.write', {
    path:protectedWritePath,
    content:'must never be written',
    encoding:'utf8',
    createParents:false,
  });
  assert(protectedWrite.isError === true, 'protected-root file.write was not rejected');
  assert(
    protectedWrite.structuredContent &&
    /MUTATION_FIREWALL_BLOCKED/.test(String(protectedWrite.structuredContent.error || '')),
    'protected-root file.write did not report MUTATION_FIREWALL_BLOCKED'
  );
  assert(!fs.existsSync(protectedWritePath), 'protected-root file.write created a file');

  const blockedFile = path.join(temp, 'must-survive-shell-delete.txt');
  fs.writeFileSync(blockedFile, 'survive me', 'utf8');
  const blocked = await callTool('shell.run', {
    shell:'powershell',
    command:"Remove-Item -LiteralPath '" + blockedFile.replace(/'/g, "''") + "' -Force",
  });
  assert(blocked.isError === true, 'shell.run destructive command was not rejected');
  assert(
    blocked.structuredContent &&
    /MUTATION_FIREWALL_BLOCKED/.test(String(blocked.structuredContent.error || '')),
    'shell.run rejection did not report MUTATION_FIREWALL_BLOCKED'
  );
  assert(fs.existsSync(blockedFile), 'shell.run deletion guard did not preserve the test file');

  const recycleFile = path.join(temp, 'gomcp-recycle-selftest-' + crypto.randomBytes(6).toString('hex') + '.txt');
  fs.writeFileSync(recycleFile, 'recycle me', 'utf8');
  const recycled = await callTool('file.delete', { path:recycleFile, force:false });
  assert(recycled.isError !== true, 'file.delete recycle operation failed');
  assert(
    recycled.structuredContent &&
    recycled.structuredContent.result &&
    recycled.structuredContent.result.quarantined === true,
    'file.delete did not report quarantined=true'
  );
  assert(!fs.existsSync(recycleFile), 'file.delete left the recycled source path in place');

  const overwriteFile = path.join(temp, 'gomcp-overwrite-selftest.txt');
  fs.writeFileSync(overwriteFile, 'old version', 'utf8');
  const rewritten = await callTool('file.write', {
    path:overwriteFile,
    content:'new version',
    encoding:'utf8',
    createParents:true,
  });
  assert(rewritten.isError !== true, 'file.write overwrite operation failed');
  assert(
    rewritten.structuredContent &&
    rewritten.structuredContent.result &&
    rewritten.structuredContent.result.priorVersionQuarantined === true,
    'file.write did not preserve the prior version through Mutation Firewall quarantine'
  );
  assert(fs.readFileSync(overwriteFile, 'utf8') === 'new version', 'file.write replacement content mismatch');

  const rootPath = path.parse(temp).root;
  const rootBlocked = await callTool('file.delete', { path:rootPath, force:false });
  assert(rootBlocked.isError === true, 'drive-root recycle attempt was not blocked');
  assert(
    rootBlocked.structuredContent &&
    /MUTATION_FIREWALL_BLOCKED/.test(String(rootBlocked.structuredContent.error || '')),
    'drive-root guard did not report MUTATION_FIREWALL_BLOCKED'
  );

  console.log('SELFTEST PASS: OAuth + 56 tools + Mutation Firewall command guard + broker gating + protected roots + quarantine semantics verified');
}

main().then(() => {
  try { child.kill(); } catch {}
  setTimeout(() => process.exit(0), 200);
}).catch(err => {
  console.error('SELFTEST FAIL:', err && err.stack ? err.stack : err);
  try { child.kill(); } catch {}
  setTimeout(() => process.exit(1), 200);
});
