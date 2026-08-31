#!/usr/bin/env node
'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const https = require('https');
const http = require('http');
const { spawn } = require('child_process');

const HOME = process.env.GOMCP_HOME || 'C:\\actions-runner\\GoMCP';
const STATE = process.env.GOMCP_STATE || path.join(HOME, 'state');
const LOGS = process.env.GOMCP_LOGS || path.join(HOME, 'logs');
const NODE = process.execPath;
const SERVER = path.join(HOME, 'gomcp.js');
const CLOUDFLARED = path.join(HOME, 'cloudflared.exe');
const RELAY_SECRET_FILE = path.join(STATE, 'relay.secret');
const TUNNEL_STATE_FILE = path.join(STATE, 'tunnel.json');
const PID_FILE = path.join(STATE, 'supervisor.pid');
const RELAY_REGISTER = process.env.GOMCP_RELAY_REGISTER || 'https://8.235.7.248/goproxy/admin/register';
const LOCAL_HEALTH = 'http://127.0.0.1:8765/health';
const RE_REGISTER_MS = 60_000;

fs.mkdirSync(STATE, { recursive: true });
fs.mkdirSync(LOGS, { recursive: true });

function log(message) {
  const line = `${new Date().toISOString()} ${message}\n`;
  process.stdout.write(line);
  try { fs.appendFileSync(path.join(LOGS, 'supervisor.log'), line, 'utf8'); } catch {}
}

function processAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch { return false; }
}

function acquirePid() {
  try {
    const old = Number(fs.readFileSync(PID_FILE, 'utf8').trim());
    if (processAlive(old)) {
      log(`existing supervisor pid=${old}; exiting duplicate`);
      process.exit(0);
    }
  } catch {}
  fs.writeFileSync(PID_FILE, String(process.pid) + '\n', 'utf8');
}

acquirePid();

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function get(url, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.get(u, { timeout: timeoutMs }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

function postJson(url, token, payload, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const body = Buffer.from(JSON.stringify(payload), 'utf8');
    const req = https.request(u, {
      method: 'POST', timeout: timeoutMs,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Content-Length': String(body.length),
        'User-Agent': 'GoMCP-Supervisor/0.1',
      },
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.write(body); req.end();
  });
}

let server = null;
let tunnel = null;
let stopping = false;
let currentUrl = '';
let registerTimer = null;

function pipeChild(child, label, logFile) {
  const file = path.join(LOGS, logFile);
  const consume = stream => {
    let buffer = '';
    stream.setEncoding('utf8');
    stream.on('data', chunk => {
      try { fs.appendFileSync(file, chunk, 'utf8'); } catch {}
      buffer += chunk;
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() || '';
      for (const line of lines) {
        if (line.trim()) log(`${label}: ${line}`);
        const m = line.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/i);
        if (m) onTunnelUrl(m[0]).catch(err => log(`register error: ${err.message}`));
      }
    });
  };
  if (child.stdout) consume(child.stdout);
  if (child.stderr) consume(child.stderr);
}

async function waitForServer() {
  for (let i = 0; i < 30 && !stopping; i++) {
    try {
      const r = await get(LOCAL_HEALTH, 1500);
      if (r.status === 200) return true;
    } catch {}
    await sleep(500);
  }
  return false;
}

function startServer() {
  if (server && processAlive(server.pid)) return;
  log('starting GoMCP server');
  server = spawn(NODE, [SERVER], {
    cwd: HOME, windowsHide: true,
    env: { ...process.env, GOMCP_HOME: HOME },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  pipeChild(server, 'server', 'server.log');
  server.on('exit', (code, signal) => {
    log(`server exited code=${code} signal=${signal}`);
    server = null;
    if (!stopping) setTimeout(startServer, 2000).unref();
  });
}

async function onTunnelUrl(url) {
  url = url.replace(/\/$/, '');
  if (currentUrl !== url) {
    currentUrl = url;
    await fsp.writeFile(TUNNEL_STATE_FILE, JSON.stringify({ url, updatedAt: new Date().toISOString() }, null, 2) + '\n', 'utf8');
    log(`quick tunnel url=${url}`);
  }
  await registerCurrent();
  if (!registerTimer) {
    registerTimer = setInterval(() => registerCurrent().catch(err => log(`periodic registration error: ${err.message}`)), RE_REGISTER_MS);
    registerTimer.unref();
  }
}

async function registerCurrent() {
  if (!currentUrl) return false;
  let secret;
  try { secret = (await fsp.readFile(RELAY_SECRET_FILE, 'utf8')).trim(); }
  catch { throw new Error(`relay secret missing: ${RELAY_SECRET_FILE}`); }
  if (!secret) throw new Error('relay secret is empty');
  const r = await postJson(RELAY_REGISTER, secret, { target: currentUrl });
  if (r.status < 200 || r.status >= 300) throw new Error(`relay registration failed status=${r.status} body=${r.body.slice(0, 300)}`);
  log(`relay registration ok target=${currentUrl}`);
  return true;
}

async function startTunnel() {
  if (tunnel && processAlive(tunnel.pid)) return;
  if (!fs.existsSync(CLOUDFLARED)) throw new Error(`cloudflared missing: ${CLOUDFLARED}`);
  if (!await waitForServer()) throw new Error('GoMCP server did not become healthy');
  currentUrl = '';
  log('starting Cloudflare Quick Tunnel');
  tunnel = spawn(CLOUDFLARED, ['tunnel', '--no-autoupdate', '--url', 'http://127.0.0.1:8765', '--loglevel', 'info'], {
    cwd: HOME, windowsHide: true,
    env: { ...process.env, HOME, USERPROFILE: HOME },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  pipeChild(tunnel, 'cloudflared', 'cloudflared.log');
  tunnel.on('exit', (code, signal) => {
    log(`cloudflared exited code=${code} signal=${signal}`);
    tunnel = null; currentUrl = '';
    if (registerTimer) { clearInterval(registerTimer); registerTimer = null; }
    if (!stopping) setTimeout(() => startTunnel().catch(err => { log(`tunnel restart failed: ${err.message}`); setTimeout(() => startTunnel().catch(e => log(`tunnel retry failed: ${e.message}`)), 5000).unref(); }), 3000).unref();
  });
}

async function main() {
  log(`GoMCP supervisor starting pid=${process.pid}`);
  startServer();
  await startTunnel();
  setInterval(async () => {
    if (stopping) return;
    if (!server || !processAlive(server.pid)) startServer();
    if (!tunnel || !processAlive(tunnel.pid)) {
      try { await startTunnel(); } catch (err) { log(`watchdog tunnel start failed: ${err.message}`); }
    }
  }, 15000).unref();
}

function shutdown(signal) {
  if (stopping) return;
  stopping = true;
  log(`supervisor stopping signal=${signal}`);
  if (registerTimer) clearInterval(registerTimer);
  try { if (tunnel) tunnel.kill(); } catch {}
  try { if (server) server.kill(); } catch {}
  try { fs.unlinkSync(PID_FILE); } catch {}
  setTimeout(() => process.exit(0), 1000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('exit', () => { try { if (Number(fs.readFileSync(PID_FILE, 'utf8').trim()) === process.pid) fs.unlinkSync(PID_FILE); } catch {} });

main().catch(err => { log(`fatal: ${err.stack || err.message}`); try { fs.unlinkSync(PID_FILE); } catch {} process.exit(1); });
