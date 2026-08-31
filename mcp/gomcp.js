#!/usr/bin/env node
'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const dns = require('dns').promises;
const { spawn, spawnSync, execFileSync } = require('child_process');

const VERSION = '0.1.0';
const PROTOCOL_CURRENT = '2026-07-28';
const PROTOCOL_LEGACY_CURRENT = '2025-11-25';
const PROTOCOL_LEGACY = new Set(['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25']);
const HOME = process.env.GOMCP_HOME || 'C:\\actions-runner\\GoMCP';
const STATE_DIR = process.env.GOMCP_STATE || path.join(HOME, 'state');
const TOKEN_FILE = process.env.GOMCP_TOKEN_FILE || path.join(STATE_DIR, 'mcp.token');
const HOST = process.env.GOMCP_HOST || '127.0.0.1';
const PORT = Number(process.env.GOMCP_PORT || '8765');
const MAX_BODY = 16 * 1024 * 1024;
const MAX_OUTPUT = 2 * 1024 * 1024;

function clampText(value, max = MAX_OUTPUT) {
  const text = value == null ? '' : String(value);
  if (Buffer.byteLength(text, 'utf8') <= max) return text;
  return text.slice(0, max) + '\n...[truncated]';
}

function ensureDirSync(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function ensureToken() {
  ensureDirSync(STATE_DIR);
  if (!fs.existsSync(TOKEN_FILE) || !fs.readFileSync(TOKEN_FILE, 'utf8').trim()) {
    fs.writeFileSync(TOKEN_FILE, crypto.randomBytes(48).toString('base64url') + '\n', { encoding: 'utf8', mode: 0o600 });
  }
  return fs.readFileSync(TOKEN_FILE, 'utf8').trim();
}

const MCP_TOKEN = ensureToken();

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function authToken(req) {
  const raw = String(req.headers.authorization || '');
  if (/^Bearer\s+/i.test(raw)) return raw.replace(/^Bearer\s+/i, '').trim();
  return String(req.headers['x-gomcp-token'] || '').trim();
}

function isAuthorized(req) {
  return safeEqual(authToken(req), MCP_TOKEN);
}

function jsonResponse(res, status, payload, extraHeaders = {}) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(body);
}

function rpcResult(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function rpcError(id, code, message, data) {
  const error = { code, message };
  if (data !== undefined) error.data = data;
  return { jsonrpc: '2.0', id: id == null ? null : id, error };
}

function run(file, args = [], opts = {}) {
  const timeoutMs = Math.max(1000, Math.min(Number(opts.timeoutMs || 60000), 300000));
  const result = spawnSync(file, args, {
    cwd: opts.cwd || undefined,
    env: opts.env ? { ...process.env, ...opts.env } : process.env,
    encoding: 'utf8',
    windowsHide: true,
    timeout: timeoutMs,
    maxBuffer: MAX_OUTPUT,
    shell: false,
  });
  return {
    ok: !result.error && result.status === 0,
    exitCode: result.status,
    signal: result.signal || null,
    stdout: clampText(result.stdout || ''),
    stderr: clampText(result.stderr || (result.error ? result.error.message : '')),
  };
}

function powershell(script, opts = {}) {
  return run('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], opts);
}

function commandExists(name) {
  const r = powershell(`$c=Get-Command ${JSON.stringify(name)} -ErrorAction SilentlyContinue; if($c){$c.Source}`);
  return r.ok ? r.stdout.trim() : '';
}

function normalizePath(p) {
  if (typeof p !== 'string' || !p.trim()) throw new Error('path is required');
  return path.resolve(p);
}

function inputSchema(properties = {}, required = []) {
  return { type: 'object', additionalProperties: false, properties, required };
}

const S = {
  string: (description) => ({ type: 'string', ...(description ? { description } : {}) }),
  integer: (description, minimum, maximum) => ({ type: 'integer', ...(description ? { description } : {}), ...(minimum != null ? { minimum } : {}), ...(maximum != null ? { maximum } : {}) }),
  boolean: (description) => ({ type: 'boolean', ...(description ? { description } : {}) }),
  arrayString: (description) => ({ type: 'array', items: { type: 'string' }, ...(description ? { description } : {}) }),
  object: (description) => ({ type: 'object', additionalProperties: { type: 'string' }, ...(description ? { description } : {}) }),
};

const TOOLS = [
  { name: 'system.info', description: 'Return Windows, Node, CPU, host and runtime identity information.', inputSchema: inputSchema() },
  { name: 'system.uptime', description: 'Return host uptime in seconds and a human-readable start time.', inputSchema: inputSchema() },
  { name: 'system.memory', description: 'Return total/free memory and Windows memory counters.', inputSchema: inputSchema() },
  { name: 'system.disks', description: 'List mounted Windows filesystem drives with capacity and free space.', inputSchema: inputSchema() },
  { name: 'system.env_get', description: 'Read one environment variable by exact name.', inputSchema: inputSchema({ name: S.string('Environment variable name') }, ['name']) },
  { name: 'system.time', description: 'Return local and UTC system time.', inputSchema: inputSchema() },
  { name: 'system.hostname', description: 'Return hostname and DNS hostname details.', inputSchema: inputSchema() },
  { name: 'system.users', description: 'List local Windows user accounts.', inputSchema: inputSchema() },
  { name: 'system.network_interfaces', description: 'List local network interfaces and addresses.', inputSchema: inputSchema() },
  { name: 'system.power', description: 'Return current Windows power plan and battery status when present.', inputSchema: inputSchema() },

  { name: 'process.list', description: 'List running processes with PID, name, CPU and working-set information.', inputSchema: inputSchema({ filter: S.string('Optional process-name substring') }) },
  { name: 'process.get', description: 'Get details for a process by PID.', inputSchema: inputSchema({ pid: S.integer('Process ID', 0) }, ['pid']) },
  { name: 'process.start', description: 'Start a detached process and return its PID.', inputSchema: inputSchema({ file: S.string('Executable or script path'), args: S.arrayString('Argument list'), cwd: S.string('Optional working directory') }, ['file']) },
  { name: 'process.stop', description: 'Stop a process by PID.', inputSchema: inputSchema({ pid: S.integer('Process ID', 1), force: S.boolean('Force termination') }, ['pid']) },
  { name: 'process.tree', description: 'Return process parent/child relationships.', inputSchema: inputSchema({ pid: S.integer('Optional root PID', 0) }) },

  { name: 'shell.run', description: 'Run a PowerShell or cmd command with timeout and capture output.', inputSchema: inputSchema({ command: S.string('Command text'), shell: { type: 'string', enum: ['powershell', 'cmd'] }, cwd: S.string('Optional working directory'), timeoutSeconds: S.integer('Timeout seconds', 1, 300) }, ['command']) },
  { name: 'shell.which', description: 'Resolve an executable or command name using Windows command discovery.', inputSchema: inputSchema({ name: S.string('Command name') }, ['name']) },

  { name: 'file.read', description: 'Read a UTF-8 text file or return base64 for binary data.', inputSchema: inputSchema({ path: S.string('File path'), encoding: { type: 'string', enum: ['utf8', 'base64'] }, maxBytes: S.integer('Maximum bytes', 1, 16777216) }, ['path']) },
  { name: 'file.write', description: 'Replace a file with UTF-8 or base64-decoded content.', inputSchema: inputSchema({ path: S.string('File path'), content: S.string('Content'), encoding: { type: 'string', enum: ['utf8', 'base64'] }, createParents: S.boolean('Create parent directories') }, ['path', 'content']) },
  { name: 'file.append', description: 'Append UTF-8 text to a file.', inputSchema: inputSchema({ path: S.string('File path'), content: S.string('Text to append'), createParents: S.boolean('Create parent directories') }, ['path', 'content']) },
  { name: 'file.list', description: 'List directory entries.', inputSchema: inputSchema({ path: S.string('Directory path'), recursive: S.boolean('Recurse'), maxEntries: S.integer('Maximum entries', 1, 10000) }, ['path']) },
  { name: 'file.stat', description: 'Return filesystem metadata for a path.', inputSchema: inputSchema({ path: S.string('Path') }, ['path']) },
  { name: 'file.mkdir', description: 'Create a directory.', inputSchema: inputSchema({ path: S.string('Directory path'), recursive: S.boolean('Create parents') }, ['path']) },
  { name: 'file.move', description: 'Move or rename a file or directory.', inputSchema: inputSchema({ source: S.string('Source path'), destination: S.string('Destination path'), overwrite: S.boolean('Replace destination if it exists') }, ['source', 'destination']) },
  { name: 'file.copy', description: 'Copy a file or directory.', inputSchema: inputSchema({ source: S.string('Source path'), destination: S.string('Destination path'), recursive: S.boolean('Copy directories recursively'), overwrite: S.boolean('Replace destination') }, ['source', 'destination']) },
  { name: 'file.delete', description: 'Delete a file or directory.', inputSchema: inputSchema({ path: S.string('Path'), recursive: S.boolean('Delete directory tree'), force: S.boolean('Ignore missing path') }, ['path']) },
  { name: 'file.hash', description: 'Calculate a file cryptographic hash.', inputSchema: inputSchema({ path: S.string('File path'), algorithm: { type: 'string', enum: ['sha256', 'sha512', 'md5'] } }, ['path']) },
  { name: 'file.tail', description: 'Read the last N lines from a text file.', inputSchema: inputSchema({ path: S.string('File path'), lines: S.integer('Line count', 1, 5000) }, ['path']) },
  { name: 'file.find', description: 'Find paths below a root using a wildcard-like name pattern.', inputSchema: inputSchema({ root: S.string('Root directory'), pattern: S.string('Case-insensitive substring or * wildcard pattern'), maxResults: S.integer('Maximum results', 1, 5000) }, ['root', 'pattern']) },

  { name: 'service.list', description: 'List Windows services.', inputSchema: inputSchema({ filter: S.string('Optional service-name/display-name substring') }) },
  { name: 'service.status', description: 'Get Windows service status.', inputSchema: inputSchema({ name: S.string('Service name') }, ['name']) },
  { name: 'service.start', description: 'Start a Windows service. Requires account permission.', inputSchema: inputSchema({ name: S.string('Service name') }, ['name']) },
  { name: 'service.stop', description: 'Stop a Windows service. Requires account permission.', inputSchema: inputSchema({ name: S.string('Service name'), force: S.boolean('Force when supported') }, ['name']) },
  { name: 'service.restart', description: 'Restart a Windows service. Requires account permission.', inputSchema: inputSchema({ name: S.string('Service name') }, ['name']) },

  { name: 'docker.ps', description: 'List Docker containers.', inputSchema: inputSchema({ all: S.boolean('Include stopped containers') }) },
  { name: 'docker.logs', description: 'Read Docker container logs.', inputSchema: inputSchema({ container: S.string('Container name or id'), tail: S.integer('Tail lines', 1, 10000), since: S.string('Optional Docker --since value') }, ['container']) },
  { name: 'docker.inspect', description: 'Inspect a Docker object.', inputSchema: inputSchema({ target: S.string('Docker object name or id') }, ['target']) },
  { name: 'docker.images', description: 'List Docker images.', inputSchema: inputSchema() },
  { name: 'docker.compose_ps', description: 'List services for a Docker Compose project.', inputSchema: inputSchema({ cwd: S.string('Compose project directory') }, ['cwd']) },
  { name: 'docker.compose_up', description: 'Start/update a Docker Compose project.', inputSchema: inputSchema({ cwd: S.string('Compose project directory'), build: S.boolean('Build images'), services: S.arrayString('Optional service names') }, ['cwd']) },
  { name: 'docker.compose_down', description: 'Stop a Docker Compose project.', inputSchema: inputSchema({ cwd: S.string('Compose project directory'), volumes: S.boolean('Remove named volumes') }, ['cwd']) },

  { name: 'git.status', description: 'Return git repository status.', inputSchema: inputSchema({ cwd: S.string('Repository directory') }, ['cwd']) },
  { name: 'git.fetch', description: 'Fetch git remotes.', inputSchema: inputSchema({ cwd: S.string('Repository directory'), remote: S.string('Remote name'), prune: S.boolean('Prune deleted refs') }, ['cwd']) },
  { name: 'git.pull', description: 'Pull a git branch.', inputSchema: inputSchema({ cwd: S.string('Repository directory'), remote: S.string('Remote name'), branch: S.string('Branch name'), ffOnly: S.boolean('Require fast-forward') }, ['cwd']) },
  { name: 'git.log', description: 'Return recent git commits.', inputSchema: inputSchema({ cwd: S.string('Repository directory'), count: S.integer('Commit count', 1, 500) }, ['cwd']) },
  { name: 'git.diff', description: 'Return git diff.', inputSchema: inputSchema({ cwd: S.string('Repository directory'), staged: S.boolean('Show staged changes'), ref: S.string('Optional ref/range') }, ['cwd']) },

  { name: 'net.listen', description: 'List listening TCP/UDP endpoints and owning PIDs.', inputSchema: inputSchema({ port: S.integer('Optional port filter', 1, 65535) }) },
  { name: 'net.resolve', description: 'Resolve a hostname using the host DNS resolver.', inputSchema: inputSchema({ hostname: S.string('Hostname') }, ['hostname']) },
  { name: 'net.ping', description: 'Ping a host.', inputSchema: inputSchema({ host: S.string('Host or IP'), count: S.integer('Echo count', 1, 20), timeoutMs: S.integer('Per-ping timeout milliseconds', 100, 10000) }, ['host']) },
  { name: 'http.request', description: 'Make an outbound HTTP(S) request and return status, headers and body.', inputSchema: inputSchema({ url: S.string('http/https URL'), method: S.string('HTTP method'), headers: S.object('Request headers'), body: S.string('Optional UTF-8 body'), timeoutSeconds: S.integer('Timeout seconds', 1, 120), maxBytes: S.integer('Maximum response bytes', 1, 10485760) }, ['url']) },
];

if (TOOLS.length !== 50) throw new Error(`Expected exactly 50 tools, got ${TOOLS.length}`);

async function listFiles(root, recursive, maxEntries) {
  const out = [];
  async function walk(dir) {
    if (out.length >= maxEntries) return;
    const entries = await fsp.readdir(dir, { withFileTypes: true });
    for (const ent of entries) {
      if (out.length >= maxEntries) break;
      const full = path.join(dir, ent.name);
      out.push({ name: ent.name, path: full, type: ent.isDirectory() ? 'directory' : ent.isFile() ? 'file' : 'other' });
      if (recursive && ent.isDirectory()) await walk(full);
    }
  }
  await walk(root);
  return out;
}

async function findFiles(root, pattern, maxResults) {
  const rxText = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  const rx = new RegExp(rxText, 'i');
  const out = [];
  async function walk(dir) {
    if (out.length >= maxResults) return;
    let entries;
    try { entries = await fsp.readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const ent of entries) {
      if (out.length >= maxResults) break;
      const full = path.join(dir, ent.name);
      if (rx.test(ent.name) || rx.test(full)) out.push(full);
      if (ent.isDirectory()) await walk(full);
    }
  }
  await walk(root);
  return out;
}

function docker(args, opts = {}) {
  return run('docker.exe', args, opts);
}

function git(args, opts = {}) {
  return run('git.exe', args, opts);
}

async function callTool(name, a) {
  a = a || {};
  switch (name) {
    case 'system.info':
      return {
        hostname: os.hostname(), platform: os.platform(), release: os.release(), arch: os.arch(),
        node: process.version, cpus: os.cpus().map(c => ({ model: c.model, speedMHz: c.speed })),
        runnerUser: process.env.USERNAME || null, gomcpVersion: VERSION,
      };
    case 'system.uptime': {
      const uptimeSeconds = os.uptime();
      return { uptimeSeconds, bootTime: new Date(Date.now() - uptimeSeconds * 1000).toISOString() };
    }
    case 'system.memory':
      return { totalBytes: os.totalmem(), freeBytes: os.freemem(), windows: powershell("Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory,TotalVirtualMemorySize,FreeVirtualMemory | ConvertTo-Json -Compress") };
    case 'system.disks':
      return powershell("Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" | Select-Object DeviceID,VolumeName,Size,FreeSpace,FileSystem | ConvertTo-Json -Compress");
    case 'system.env_get':
      return { name: a.name, value: process.env[a.name] ?? null };
    case 'system.time':
      return { local: new Date().toString(), utc: new Date().toISOString(), timezone: Intl.DateTimeFormat().resolvedOptions().timeZone };
    case 'system.hostname':
      return { hostname: os.hostname(), fqdn: powershell('[System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName').stdout.trim() || null };
    case 'system.users':
      return powershell("Get-LocalUser | Select-Object Name,Enabled,LastLogon,SID | ConvertTo-Json -Compress");
    case 'system.network_interfaces':
      return { node: os.networkInterfaces(), windows: powershell("Get-NetIPConfiguration | Select-Object InterfaceAlias,InterfaceDescription,IPv4Address,IPv6Address,IPv4DefaultGateway,DNSServer | ConvertTo-Json -Depth 5 -Compress") };
    case 'system.power':
      return { plan: run('powercfg.exe', ['/GETACTIVESCHEME']), battery: powershell("Get-CimInstance Win32_Battery | Select-Object Name,EstimatedChargeRemaining,BatteryStatus,EstimatedRunTime | ConvertTo-Json -Compress") };

    case 'process.list': {
      const filter = String(a.filter || '').replace(/'/g, "''");
      const where = filter ? ` | Where-Object { $_.ProcessName -like '*${filter}*' }` : '';
      return powershell(`Get-Process${where} | Select-Object Id,ProcessName,CPU,WorkingSet64,Path,StartTime -ErrorAction SilentlyContinue | ConvertTo-Json -Compress`);
    }
    case 'process.get':
      return powershell(`Get-CimInstance Win32_Process -Filter \"ProcessId=${Number(a.pid)}\" | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate | ConvertTo-Json -Compress`);
    case 'process.start': {
      const child = spawn(a.file, Array.isArray(a.args) ? a.args : [], { cwd: a.cwd || undefined, detached: true, stdio: 'ignore', windowsHide: true });
      child.unref();
      return { ok: true, pid: child.pid };
    }
    case 'process.stop':
      process.kill(Number(a.pid), a.force ? 'SIGKILL' : 'SIGTERM'); return { ok: true, pid: Number(a.pid) };
    case 'process.tree': {
      const all = powershell("Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Json -Compress");
      if (!a.pid) return all;
      if (!all.ok) return all;
      let rows; try { rows = JSON.parse(all.stdout || '[]'); } catch { return all; }
      if (!Array.isArray(rows)) rows = rows ? [rows] : [];
      const root = Number(a.pid); const keep = new Set([root]); let changed = true;
      while (changed) { changed = false; for (const r of rows) if (keep.has(Number(r.ParentProcessId)) && !keep.has(Number(r.ProcessId))) { keep.add(Number(r.ProcessId)); changed = true; } }
      return rows.filter(r => keep.has(Number(r.ProcessId)));
    }

    case 'shell.run': {
      const timeoutMs = (a.timeoutSeconds || 60) * 1000;
      if ((a.shell || 'powershell') === 'cmd') return run('cmd.exe', ['/d', '/s', '/c', a.command], { cwd: a.cwd, timeoutMs });
      return powershell(a.command, { cwd: a.cwd, timeoutMs });
    }
    case 'shell.which': {
      const found = commandExists(a.name); return { name: a.name, path: found || null };
    }

    case 'file.read': {
      const p = normalizePath(a.path); const max = Math.min(Number(a.maxBytes || MAX_BODY), MAX_BODY);
      const fh = await fsp.open(p, 'r');
      try { const stat = await fh.stat(); const len = Math.min(stat.size, max); const b = Buffer.alloc(len); await fh.read(b, 0, len, 0); return { path: p, size: stat.size, truncated: stat.size > len, encoding: a.encoding || 'utf8', content: (a.encoding === 'base64' ? b.toString('base64') : b.toString('utf8')) }; } finally { await fh.close(); }
    }
    case 'file.write': {
      const p = normalizePath(a.path); if (a.createParents !== false) await fsp.mkdir(path.dirname(p), { recursive: true });
      const data = a.encoding === 'base64' ? Buffer.from(a.content, 'base64') : Buffer.from(a.content, 'utf8'); await fsp.writeFile(p, data); return { ok: true, path: p, bytes: data.length };
    }
    case 'file.append': {
      const p = normalizePath(a.path); if (a.createParents !== false) await fsp.mkdir(path.dirname(p), { recursive: true }); await fsp.appendFile(p, String(a.content), 'utf8'); return { ok: true, path: p };
    }
    case 'file.list': return listFiles(normalizePath(a.path), !!a.recursive, Number(a.maxEntries || 2000));
    case 'file.stat': {
      const p = normalizePath(a.path), st = await fsp.stat(p); return { path: p, size: st.size, mode: st.mode, isFile: st.isFile(), isDirectory: st.isDirectory(), created: st.birthtime.toISOString(), modified: st.mtime.toISOString(), accessed: st.atime.toISOString() };
    }
    case 'file.mkdir': { const p = normalizePath(a.path); await fsp.mkdir(p, { recursive: a.recursive !== false }); return { ok: true, path: p }; }
    case 'file.move': {
      const s = normalizePath(a.source), d = normalizePath(a.destination); if (a.overwrite) await fsp.rm(d, { recursive: true, force: true }).catch(() => {}); await fsp.mkdir(path.dirname(d), { recursive: true }); await fsp.rename(s, d); return { ok: true, source: s, destination: d };
    }
    case 'file.copy': {
      const s = normalizePath(a.source), d = normalizePath(a.destination); if (a.overwrite) await fsp.rm(d, { recursive: true, force: true }).catch(() => {}); const st = await fsp.stat(s); await fsp.mkdir(path.dirname(d), { recursive: true }); if (st.isDirectory()) { if (!a.recursive) throw new Error('source is a directory; recursive=true required'); await fsp.cp(s, d, { recursive: true, force: !!a.overwrite }); } else await fsp.copyFile(s, d); return { ok: true, source: s, destination: d };
    }
    case 'file.delete': { const p = normalizePath(a.path); await fsp.rm(p, { recursive: !!a.recursive, force: !!a.force }); return { ok: true, path: p }; }
    case 'file.hash': {
      const p = normalizePath(a.path), algo = a.algorithm || 'sha256'; const h = crypto.createHash(algo); await new Promise((resolve, reject) => { const s = fs.createReadStream(p); s.on('data', d => h.update(d)); s.on('error', reject); s.on('end', resolve); }); return { path: p, algorithm: algo, hash: h.digest('hex') };
    }
    case 'file.tail': { const p = normalizePath(a.path); const text = await fsp.readFile(p, 'utf8'); const lines = text.split(/\r?\n/); return { path: p, lines: lines.slice(-Number(a.lines || 100)).join('\n') }; }
    case 'file.find': return findFiles(normalizePath(a.root), String(a.pattern), Number(a.maxResults || 1000));

    case 'service.list': {
      const filter = String(a.filter || '').replace(/'/g, "''"); const where = filter ? ` | Where-Object { $_.Name -like '*${filter}*' -or $_.DisplayName -like '*${filter}*' }` : ''; return powershell(`Get-Service${where} | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Compress`);
    }
    case 'service.status': return powershell(`Get-Service -Name ${JSON.stringify(a.name)} | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Compress`);
    case 'service.start': return powershell(`Start-Service -Name ${JSON.stringify(a.name)} -ErrorAction Stop; Get-Service -Name ${JSON.stringify(a.name)} | Select-Object Name,Status | ConvertTo-Json -Compress`);
    case 'service.stop': return powershell(`Stop-Service -Name ${JSON.stringify(a.name)} ${a.force ? '-Force' : ''} -ErrorAction Stop; Get-Service -Name ${JSON.stringify(a.name)} | Select-Object Name,Status | ConvertTo-Json -Compress`);
    case 'service.restart': return powershell(`Restart-Service -Name ${JSON.stringify(a.name)} -ErrorAction Stop; Get-Service -Name ${JSON.stringify(a.name)} | Select-Object Name,Status | ConvertTo-Json -Compress`);

    case 'docker.ps': return docker(['ps', ...(a.all ? ['-a'] : []), '--format', '{{json .}}']);
    case 'docker.logs': return docker(['logs', '--tail', String(a.tail || 200), ...(a.since ? ['--since', String(a.since)] : []), a.container]);
    case 'docker.inspect': return docker(['inspect', a.target]);
    case 'docker.images': return docker(['images', '--format', '{{json .}}']);
    case 'docker.compose_ps': return docker(['compose', 'ps', '--format', 'json'], { cwd: a.cwd });
    case 'docker.compose_up': return docker(['compose', 'up', '-d', ...(a.build ? ['--build'] : []), ...(Array.isArray(a.services) ? a.services : [])], { cwd: a.cwd, timeoutMs: 300000 });
    case 'docker.compose_down': return docker(['compose', 'down', ...(a.volumes ? ['-v'] : [])], { cwd: a.cwd, timeoutMs: 300000 });

    case 'git.status': return git(['status', '--short', '--branch'], { cwd: a.cwd });
    case 'git.fetch': return git(['fetch', a.remote || 'origin', ...(a.prune ? ['--prune'] : [])], { cwd: a.cwd, timeoutMs: 300000 });
    case 'git.pull': return git(['pull', ...(a.ffOnly !== false ? ['--ff-only'] : []), a.remote || 'origin', ...(a.branch ? [a.branch] : [])], { cwd: a.cwd, timeoutMs: 300000 });
    case 'git.log': return git(['log', `-${Number(a.count || 30)}`, '--date=iso-strict', '--pretty=format:%H%x09%ad%x09%an%x09%s'], { cwd: a.cwd });
    case 'git.diff': return git(['diff', ...(a.staged ? ['--cached'] : []), ...(a.ref ? [a.ref] : [])], { cwd: a.cwd });

    case 'net.listen': {
      const r = run('netstat.exe', ['-ano']); if (!a.port || !r.stdout) return r; const p = `:${Number(a.port)} `; return { ...r, stdout: r.stdout.split(/\r?\n/).filter(line => line.includes(p)).join('\n') };
    }
    case 'net.resolve': return { hostname: a.hostname, addresses: await dns.lookup(a.hostname, { all: true }) };
    case 'net.ping': return run('ping.exe', ['-n', String(a.count || 4), '-w', String(a.timeoutMs || 2000), a.host], { timeoutMs: Math.min(300000, (a.count || 4) * (a.timeoutMs || 2000) + 5000) });
    case 'http.request': return await httpRequest(a);
    default: throw new Error(`Unknown tool: ${name}`);
  }
}

function httpRequest(a) {
  return new Promise((resolve, reject) => {
    const u = new URL(a.url);
    if (!['http:', 'https:'].includes(u.protocol)) return reject(new Error('url must use http or https'));
    const transport = u.protocol === 'https:' ? https : http;
    const body = a.body == null ? null : Buffer.from(String(a.body), 'utf8');
    const headers = { ...(a.headers || {}) };
    if (body && !Object.keys(headers).some(k => k.toLowerCase() === 'content-length')) headers['Content-Length'] = String(body.length);
    const req = transport.request(u, { method: String(a.method || 'GET').toUpperCase(), headers, timeout: (a.timeoutSeconds || 30) * 1000 }, res => {
      const chunks = []; let total = 0; const max = Number(a.maxBytes || 2 * 1024 * 1024);
      res.on('data', chunk => { total += chunk.length; if (total <= max) chunks.push(chunk); });
      res.on('end', () => resolve({ status: res.statusCode, statusMessage: res.statusMessage, headers: res.headers, truncated: total > max, bytes: total, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('timeout', () => req.destroy(new Error('request timed out')));
    req.on('error', reject); if (body) req.write(body); req.end();
  });
}

function requestProtocol(req, body) {
  const headerVersion = String(req.headers['mcp-protocol-version'] || '').trim();
  const meta = body && body.params && body.params._meta;
  const metaVersion = meta && typeof meta === 'object'
    ? String(meta['io.modelcontextprotocol/protocolVersion'] || '').trim()
    : '';
  if (body && body.method === 'initialize') {
    const requested = body.params && String(body.params.protocolVersion || '').trim();
    return { era: 'legacy', version: PROTOCOL_LEGACY.has(requested) ? requested : PROTOCOL_LEGACY_CURRENT };
  }
  if (headerVersion) {
    if (headerVersion === PROTOCOL_CURRENT) return { era: 'modern', version: headerVersion };
    if (PROTOCOL_LEGACY.has(headerVersion)) return { era: 'legacy', version: headerVersion };
    throw new Error(`Unsupported MCP-Protocol-Version ${headerVersion}`);
  }
  if (metaVersion) {
    if (metaVersion === PROTOCOL_CURRENT) return { era: 'modern', version: metaVersion };
    if (PROTOCOL_LEGACY.has(metaVersion)) return { era: 'legacy', version: metaVersion };
    throw new Error(`Unsupported MCP protocol version ${metaVersion}`);
  }
  return { era: 'legacy', version: '2025-03-26' };
}

function validateProtocolHeaders(req, body) {
  const protocol = requestProtocol(req, body);
  const method = req.headers['mcp-method'];
  const name = req.headers['mcp-name'];
  if (method && method !== body.method) throw new Error('Mcp-Method header does not match JSON-RPC method');
  const bodyName = body.params && (body.params.name || body.params.uri || body.params.taskId);
  if (name && bodyName && name !== bodyName) throw new Error('Mcp-Name header does not match request parameter');
  return protocol;
}

function modernResult(result, protocol) {
  if (!protocol || protocol.era !== 'modern') return result;
  const existing = result && result._meta && typeof result._meta === 'object' ? result._meta : {};
  return {
    ...result,
    _meta: {
      ...existing,
      'io.modelcontextprotocol/serverInfo': { name: 'GoMCP', version: VERSION },
    },
  };
}

async function handleRpc(req, res, body) {
  const id = body.id;
  const method = body.method;
  try {
    const protocol = validateProtocolHeaders(req, body);
    if (method === 'initialize') {
      const requested = body.params && String(body.params.protocolVersion || '').trim();
      const protocolVersion = PROTOCOL_LEGACY.has(requested) ? requested : PROTOCOL_LEGACY_CURRENT;
      return jsonResponse(res, 200, rpcResult(id, {
        protocolVersion,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'GoMCP', version: VERSION },
      }));
    }
    if (method === 'notifications/initialized') {
      res.writeHead(202, { 'Cache-Control': 'no-store' });
      return res.end();
    }
    if (method === 'ping') return jsonResponse(res, 200, rpcResult(id, modernResult({}, protocol)));
    if (method === 'server/discover') {
      const result = {
        supportedVersions: [PROTOCOL_CURRENT],
        capabilities: { tools: { listChanged: false } },
        ttlMs: 300000,
        cacheScope: 'public',
      };
      return jsonResponse(res, 200, rpcResult(id, modernResult(result, { era: 'modern', version: PROTOCOL_CURRENT })));
    }
    if (method === 'tools/list') {
      const result = { tools: TOOLS };
      if (protocol.era === 'modern') {
        result.ttlMs = 300000;
        result.cacheScope = 'private';
      }
      return jsonResponse(res, 200, rpcResult(id, modernResult(result, protocol)));
    }
    if (method === 'tools/call') {
      const params = body.params || {};
      const toolName = params.name;
      if (!toolName) throw new Error('params.name is required');
      const started = Date.now();
      try {
        const result = await callTool(toolName, params.arguments || {});
        const structured = { ok: true, tool: toolName, durationMs: Date.now() - started, result };
        const callResult = { content: [{ type: 'text', text: clampText(JSON.stringify(structured, null, 2)) }], structuredContent: structured, isError: false };
        return jsonResponse(res, 200, rpcResult(id, modernResult(callResult, protocol)));
      } catch (err) {
        const structured = { ok: false, tool: toolName, durationMs: Date.now() - started, error: err && err.message ? err.message : String(err) };
        const callResult = { content: [{ type: 'text', text: JSON.stringify(structured) }], structuredContent: structured, isError: true };
        return jsonResponse(res, 200, rpcResult(id, modernResult(callResult, protocol)));
      }
    }
    return jsonResponse(res, 200, rpcError(id, -32601, `Method not found: ${method}`));
  } catch (err) {
    return jsonResponse(res, 400, rpcError(id, -32602, err && err.message ? err.message : String(err)));
  }
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    return jsonResponse(res, 200, { ok: true, service: 'gomcp', version: VERSION, toolCount: TOOLS.length, host: os.hostname(), protocol: [PROTOCOL_LEGACY, PROTOCOL_CURRENT] });
  }
  if (req.url !== '/mcp') return jsonResponse(res, 404, { ok: false, error: 'not_found' });
  if (!isAuthorized(req)) return jsonResponse(res, 401, { ok: false, error: 'unauthorized' }, { 'WWW-Authenticate': 'Bearer realm="GoMCP"' });
  if (req.method !== 'POST') return jsonResponse(res, 405, { ok: false, error: 'method_not_allowed' }, { Allow: 'POST' });

  let total = 0; const chunks = [];
  req.on('data', chunk => {
    total += chunk.length;
    if (total > MAX_BODY) { req.destroy(); return; }
    chunks.push(chunk);
  });
  req.on('end', async () => {
    if (total > MAX_BODY) return jsonResponse(res, 413, rpcError(null, -32000, 'request too large'));
    let body;
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return jsonResponse(res, 400, rpcError(null, -32700, 'Parse error')); }
    if (!body || body.jsonrpc !== '2.0' || typeof body.method !== 'string') return jsonResponse(res, 400, rpcError(body && body.id, -32600, 'Invalid Request'));
    await handleRpc(req, res, body);
  });
});

server.keepAliveTimeout = 65000;
server.headersTimeout = 70000;
server.requestTimeout = 310000;
server.listen(PORT, HOST, () => console.log(`GoMCP ${VERSION} listening on http://${HOST}:${PORT}/mcp with ${TOOLS.length} tools`));

function shutdown(signal) {
  console.log(`GoMCP received ${signal}; shutting down`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
