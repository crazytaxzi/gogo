#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const { spawn } = require('child_process');

const HOME = process.env.GOMCP_HOME || 'C:\\actions-runner\\GoMCP';
const STATE = process.env.GOMCP_STATE || path.join(HOME, 'state');
const LOGS = process.env.GOMCP_LOGS || path.join(HOME, 'logs');
const SERVER = path.join(HOME, 'gomcp.js');
const PID_FILE = path.join(STATE, 'supervisor.pid');
const NODE = process.execPath;
const PORT = String(process.env.GOMCP_PORT || '8882');
const HEALTH = 'http://127.0.0.1:' + PORT + '/health';

fs.mkdirSync(STATE, { recursive: true });
fs.mkdirSync(LOGS, { recursive: true });

function log(message) {
  const line = new Date().toISOString() + ' ' + message + '\n';
  process.stdout.write(line);
  try { fs.appendFileSync(path.join(LOGS, 'supervisor.log'), line, 'utf8'); } catch {}
}

function alive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch { return false; }
}

try {
  const old = Number(fs.readFileSync(PID_FILE, 'utf8').trim());
  if (alive(old)) {
    log('supervisor already running pid=' + old + '; exiting duplicate');
    process.exit(0);
  }
} catch {}
fs.writeFileSync(PID_FILE, String(process.pid) + '\n', 'utf8');

let child = null;
let stopping = false;

function pipe(stream, label) {
  if (!stream) return;
  const file = path.join(LOGS, label + '.log');
  stream.on('data', chunk => { try { fs.appendFileSync(file, chunk); } catch {} });
}

function startChild() {
  if (stopping || (child && alive(child.pid))) return;
  if (!fs.existsSync(SERVER)) throw new Error('gomcp.js missing: ' + SERVER);
  child = spawn(NODE, [SERVER], {
    cwd: HOME,
    windowsHide: true,
    env: {
      ...process.env,
      GOMCP_HOME: HOME,
      GOMCP_STATE: STATE,
      GOMCP_PORT: PORT,
      GOMCP_PUBLIC_BASE: process.env.GOMCP_PUBLIC_BASE || 'https://gamepc-mcp.sentionce.net'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  pipe(child.stdout, 'server');
  pipe(child.stderr, 'server-error');
  log('started GoMCP child pid=' + child.pid);
  child.on('exit', (code, signal) => {
    log('GoMCP child exited code=' + code + ' signal=' + signal);
    child = null;
    if (!stopping) setTimeout(() => {
      try { startChild(); } catch (err) { log('restart failed: ' + err.message); }
    }, 2000).unref();
  });
}

function healthCheck() {
  return new Promise(resolve => {
    const req = http.get(HEALTH, { timeout: 2500 }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          resolve(res.statusCode === 200 && body.ok === true && body.toolCount === 56);
        } catch { resolve(false); }
      });
    });
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
  });
}

startChild();
setInterval(async () => {
  if (stopping) return;
  if (!child || !alive(child.pid)) {
    try { startChild(); } catch (err) { log('watchdog start failed: ' + err.message); }
    return;
  }
  if (!await healthCheck()) log('health probe not healthy yet');
}, 15000).unref();

function shutdown(signal) {
  if (stopping) return;
  stopping = true;
  log('supervisor stopping signal=' + signal);
  try { if (child) child.kill(); } catch {}
  try { fs.unlinkSync(PID_FILE); } catch {}
  setTimeout(() => process.exit(0), 1000).unref();
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('exit', () => {
  try {
    if (Number(fs.readFileSync(PID_FILE, 'utf8').trim()) === process.pid) fs.unlinkSync(PID_FILE);
  } catch {}
});
