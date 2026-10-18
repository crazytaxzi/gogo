'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function createDrive(options) {
  const root = options.root || 'E:\\GoMCPdrive';
  const up = path.join(root, 'Up');
  const down = path.join(root, 'Down');
  const publicBase = String(options.publicBase || '').replace(/\/+$/, '');
  const secret = crypto.createHash('sha256').update(String(options.signingToken || '')).update('GoMCPdrive-v1').digest();

  function dir(direction) {
    const d = String(direction || '').toLowerCase();
    if (d === 'up') return up;
    if (d === 'down') return down;
    throw new Error('direction must be up or down');
  }

  function basename(filename) {
    const value = String(filename || '');
    const base = path.basename(value);
    if (!value || base !== value || value === '.' || value === '..') throw new Error('filename must be a basename only');
    return base;
  }

  function signature(direction, expires, filename) {
    return crypto.createHmac('sha256', secret)
      .update(direction + '\n' + String(expires) + '\n' + filename)
      .digest('hex');
  }

  async function list(direction) {
    const target = dir(direction);
    await fsp.mkdir(target, { recursive:true });
    const entries = await fsp.readdir(target, { withFileTypes:true });
    const files = [];
    for (const ent of entries) {
      if (!ent.isFile()) continue;
      const full = path.join(target, ent.name);
      const st = await fsp.stat(full);
      files.push({ name:ent.name, bytes:st.size, modifiedAt:st.mtime.toISOString() });
    }
    files.sort((a,b) => a.name.localeCompare(b.name));
    return { direction:String(direction).toLowerCase(), directory:target, files };
  }

  function link(direction, filename, ttlSeconds) {
    const d = String(direction || '').toLowerCase();
    dir(d);
    const name = basename(filename);
    const ttl = Math.max(60, Math.min(Number(ttlSeconds || 3600), 86400));
    const expires = Math.floor(Date.now()/1000) + ttl;
    const sig = signature(d, expires, name);
    return {
      direction:d,
      filename:name,
      expiresAt:new Date(expires*1000).toISOString(),
      method:d === 'up' ? 'GET' : 'PUT',
      url:publicBase + '/drive/' + encodeURIComponent(d) + '/' + encodeURIComponent(name) +
        '?expires=' + expires + '&sig=' + encodeURIComponent(sig),
    };
  }

  async function handleHttp(req, res, requestUrl) {
    const parts = requestUrl.pathname.split('/').filter(Boolean);
    if (parts.length !== 3 || parts[0] !== 'drive') return false;
    const direction = decodeURIComponent(parts[1]);
    const filename = basename(decodeURIComponent(parts[2]));
    const expires = Number(requestUrl.searchParams.get('expires') || 0);
    const sig = requestUrl.searchParams.get('sig') || '';
    const expected = signature(direction, expires, filename);

    function reply(status, payload, extra) {
      const body = Buffer.from(JSON.stringify(payload), 'utf8');
      res.writeHead(status, {
        'Content-Type':'application/json; charset=utf-8',
        'Content-Length':body.length,
        'Cache-Control':'no-store',
        ...(extra || {}),
      });
      res.end(body);
    }

    if (!Number.isFinite(expires) || expires < Math.floor(Date.now()/1000)) {
      reply(403, { ok:false, error:'link_expired' }); return true;
    }
    if (!safeEqual(sig, expected)) {
      reply(403, { ok:false, error:'bad_signature' }); return true;
    }

    const targetDir = dir(direction);
    await fsp.mkdir(targetDir, { recursive:true });
    const full = path.join(targetDir, filename);

    if (direction === 'up') {
      if (!['GET','HEAD'].includes(req.method)) {
        reply(405, { ok:false, error:'method_not_allowed' }, { Allow:'GET, HEAD' }); return true;
      }
      let st;
      try { st = await fsp.stat(full); }
      catch { reply(404, { ok:false, error:'file_not_found' }); return true; }
      if (!st.isFile()) { reply(404, { ok:false, error:'file_not_found' }); return true; }
      res.writeHead(200, {
        'Content-Type':'application/octet-stream',
        'Content-Length':st.size,
        'Content-Disposition':'attachment; filename="' + filename.replace(/"/g, '') + '"',
        'Cache-Control':'no-store',
      });
      if (req.method === 'HEAD') { res.end(); return true; }
      fs.createReadStream(full).pipe(res);
      return true;
    }

    if (!['PUT','POST'].includes(req.method)) {
      reply(405, { ok:false, error:'method_not_allowed' }, { Allow:'PUT, POST' }); return true;
    }

    const tmp = full + '.upload-' + process.pid + '-' + Date.now();
    const stream = fs.createWriteStream(tmp, { flags:'wx' });
    let total = 0;
    const limit = Number(process.env.GOMCP_DRIVE_MAX_BYTES || 2 * 1024 * 1024 * 1024);

    try {
      await new Promise((resolve,reject) => {
        req.on('data', chunk => {
          total += chunk.length;
          if (total > limit) {
            reject(new Error('upload exceeds configured limit'));
            try { req.destroy(); } catch {}
            return;
          }
          if (!stream.write(chunk)) {
            req.pause();
            stream.once('drain', () => req.resume());
          }
        });
        req.on('end', () => stream.end(resolve));
        req.on('error', reject);
        stream.on('error', reject);
      });
      await fsp.rename(tmp, full);
      reply(200, { ok:true, filename, bytes:total, path:full });
      return true;
    } catch (err) {
      try { stream.destroy(); } catch {}
      try { await fsp.unlink(tmp); } catch {}
      reply(400, { ok:false, error:err && err.message ? err.message : String(err) });
      return true;
    }
  }

  return { list, link, handleHttp };
}

module.exports = { createDrive };
