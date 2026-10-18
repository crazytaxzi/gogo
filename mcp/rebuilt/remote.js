'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const crypto = require('crypto');

function parseRpcEnvelope(textBody, contentType) {
  const type = String(contentType || '').toLowerCase();

  if (type.includes('text/event-stream') || /^\s*(?:event:|data:)/m.test(textBody)) {
    const events = String(textBody || '').split(/\r?\n\r?\n/);
    let last = null;

    for (const event of events) {
      const data = event
        .split(/\r?\n/)
        .filter(line => line.startsWith('data:'))
        .map(line => line.slice(5).replace(/^\s/, ''))
        .join('\n')
        .trim();

      if (!data || data === '[DONE]') continue;

      try {
        last = JSON.parse(data);
      } catch {}
    }

    if (last) return last;
    throw new Error('Remote MCP returned SSE without a JSON data event');
  }

  try {
    return JSON.parse(textBody);
  } catch {
    throw new Error('Remote MCP returned neither JSON nor parseable SSE');
  }
}

function createRemote(options) {
  const configFile = options.configFile;
  const protocolVersion = options.protocolVersion || '2025-11-25';

  function loadTargets() {
    let parsed;
    try { parsed = JSON.parse(fs.readFileSync(configFile, 'utf8')); }
    catch (err) { throw new Error('Unable to read remote target config: ' + (err && err.message ? err.message : String(err))); }
    if (!parsed || !Array.isArray(parsed.targets)) throw new Error('remote-targets.json has no targets array');
    return parsed.targets;
  }

  function getTarget(name) {
    const wanted = String(name || '').trim().toLowerCase();
    if (!wanted) throw new Error('target is required');
    const target = loadTargets().find(t => {
      if (String(t.name || '').trim().toLowerCase() === wanted) return true;
      return Array.isArray(t.aliases) && t.aliases.some(a => String(a).trim().toLowerCase() === wanted);
    });
    if (!target) throw new Error('Unknown remote target: ' + name);
    if (target.enabled === false) throw new Error('Remote target is disabled: ' + target.name);
    return target;
  }

  function targetToken(target) {
    if (!target.token_file) return '';
    const tokenPath = path.isAbsolute(target.token_file)
      ? target.token_file
      : path.resolve(path.dirname(configFile), target.token_file);
    const token = fs.readFileSync(tokenPath, 'utf8').trim();
    if (!token) throw new Error('Remote target token is empty: ' + target.name);
    return token;
  }

  function rpc(targetName, method, params) {
    const target = getTarget(targetName);
    const endpoint = new URL(target.base_url);
    const token = targetToken(target);
    const body = Buffer.from(JSON.stringify({
      jsonrpc:'2.0',
      id:crypto.randomBytes(8).toString('hex'),
      method,
      params:params || {},
    }), 'utf8');

    return new Promise((resolve,reject) => {
      const transport = endpoint.protocol === 'https:' ? https : http;
      const headers = {
        'Content-Type':'application/json',
        'Accept':'application/json, text/event-stream',
        'Content-Length':String(body.length),
        'MCP-Protocol-Version':protocolVersion,
      };
      if (token) headers.Authorization = 'Bearer ' + token;
      const req = transport.request(endpoint, {
        method:'POST',
        headers,
        timeout:Number(target.timeout_ms || 15000),
      }, res => {
        const chunks = [];
        let total = 0;
        const max = 8 * 1024 * 1024;
        res.on('data', chunk => {
          total += chunk.length;
          if (total <= max) chunks.push(chunk);
        });
        res.on('end', () => {
          const textBody = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode < 200 || res.statusCode >= 300) {
            reject(new Error('Remote MCP HTTP ' + res.statusCode + ': ' + textBody.slice(0, 500)));
            return;
          }
          let parsed;
          try { parsed = parseRpcEnvelope(textBody, res.headers['content-type']); }
          catch (err) { reject(err); return; }
          if (parsed.error) { reject(new Error(parsed.error.message || JSON.stringify(parsed.error))); return; }
          resolve(parsed.result);
        });
      });
      req.on('timeout', () => req.destroy(new Error('Remote MCP request timed out')));
      req.on('error', reject);
      req.write(body);
      req.end();
    });
  }

  function targets() {
    return {
      targets:loadTargets().filter(t => t.enabled !== false).map(t => ({
        name:t.name,
        base_url:t.base_url,
        enabled:t.enabled !== false,
        description:t.description || null,
      })),
    };
  }

  async function health(name) {
    const target = getTarget(name);
    return {
      target:target.name,
      ping:await rpc(target.name, 'tools/call', { name:'mcp.ping', arguments:{} }),
    };
  }

  async function listTools(name) {
    const target = getTarget(name);
    const listed = await rpc(target.name, 'tools/list', {});
    return {
      target:target.name,
      tools:(listed.tools || []).map(t => ({
        name:t.name,
        title:t.title || null,
        description:t.description || '',
        inputSchema:t.inputSchema || {},
        annotations:t.annotations || {},
        _meta:t._meta || {},
      })),
    };
  }

  async function call(name, tool, args) {
    if (String(tool || '').startsWith('remote.')) throw new Error('Remote recursion is not allowed');
    const target = getTarget(name);
    const result = await rpc(target.name, 'tools/call', { name:String(tool), arguments:args || {} });
    return { target:target.name, tool:String(tool), result };
  }

  return { targets, health, listTools, call };
}

module.exports = { createRemote };
