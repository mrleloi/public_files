'use strict';
const net = require('net');

const STX = 0x04, HDR = 0x20, ETX = 0x03;
const frame = (payload) => {
  const len = Buffer.byteLength(payload, 'ascii');
  const b = Buffer.allocUnsafe(7 + len);
  b[0] = STX; b[1] = HDR; b.writeUInt32BE(len, 2); b.write(payload, 6, len, 'ascii'); b[6 + len] = ETX;
  return b;
};
const msg = (f) => Object.entries(f).map(([k, v]) => `${k}=${v}`).join('|');
const parse = (p) => { const o = {}; for (const kv of p.split('|')) { const i = kv.indexOf('='); if (i > 0) { const k = kv.slice(0, i); (o[k] = o[k] || []).push(kv.slice(i + 1)); } } return o; };
const redact = (p) => p.replace(/5029=[^|]*/g, '5029=<REDACTED>');

function conn(host, port, label) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host, port });
    let buf = Buffer.alloc(0); const frames = []; const waiters = [];
    s.setTimeout(15000, () => { s.destroy(new Error(`${label}: socket timeout`)); });
    s.on('data', (c) => {
      buf = buf.length ? Buffer.concat([buf, c]) : c;
      while (buf.length >= 7) {
        if (buf[0] !== STX || buf[1] !== HDR) { const i = buf.indexOf(STX, 1); buf = i < 0 ? Buffer.alloc(0) : buf.slice(i); continue; }
        const n = buf.readUInt32BE(2); if (buf.length < 7 + n) break;
        const p = buf.slice(6, 6 + n).toString('ascii'); buf = buf.slice(7 + n);
        frames.push(p); for (const w of waiters.slice()) w(p);
      }
    });
    s.on('error', (e) => { if (!s._ok) reject(e); else console.log(`[${label}] socket error: ${e.message}`); });
    s.on('connect', () => { s._ok = true; resolve({ s, frames, waiters, label }); });
  });
}
// wait for the frame carrying 5026=<tag> AND 5001 (the command status); collect every frame of that tag
function cmd(c, fields, waitMs = 8000) {
  const tag = String(fields['5026']);
  return new Promise((resolve) => {
    const got = [];
    const done = (why) => { c.waiters.splice(c.waiters.indexOf(w), 1); clearTimeout(t); resolve({ why, frames: got }); };
    // every CTF command response (incl. ListUserPermission, one frame: 5026=1|3=..|3=..|5001=0) ends with 5001
    const w = (p) => { const o = parse(p); if ((o['5026'] || [])[0] !== tag) return; got.push(p); if (o['5001']) done('status'); };
    const t = setTimeout(() => done('timeout'), waitMs);
    c.waiters.push(w);
    c.s.write(frame(msg(fields)));
  });
}
const status = (r) => { for (const p of r.frames) { const o = parse(p); if (o['5001']) return o['5001'][0]; } return `none(${r.why})`; };

async function login(c, acct, tag) {
  const r = await cmd(c, { 5022: 'LoginUser', 5026: tag, 5028: acct.username, 5029: acct.password, 13265: 0, 5079: 0 });
  const st = status(r);
  console.log(`[${c.label}] LoginUser as ${acct.username} -> 5001=${st}`);
  return st === '0';
}

(async () => {
  const pool = JSON.parse(process.env.ICE_ACCOUNT_POOL_JSON || '[]');
  console.log('pool entries (no secrets):');
  for (const a of pool) console.log(`  ${a.accountId} user=${a.username} set=${a.setId} ${a.servingType} ${a.cspIp}:${a.cspPort}`);
  console.log(`ICE_REALTIME_L2_SOURCES=${process.env.ICE_REALTIME_L2_SOURCES || '(unset => code default "938")'}`);
  const want = (process.env.ACC || 'uobtest3').toLowerCase();
  const cands = pool.filter((a) => `${a.accountId} ${a.username}`.toLowerCase().includes(want));
  const acct = cands.find((a) => !process.env.PROBE_HOST || a.cspIp === process.env.PROBE_HOST) || cands[0];
  if (!acct || !acct.password) { console.log(`no pool entry with credentials matches ACC=${want}`); process.exit(2); }
  const host = process.env.PROBE_HOST || acct.cspIp; const port = Number(process.env.PROBE_PORT || acct.cspPort);
  const sources = (process.env.SOURCES || '641,938').split(',').map((x) => x.trim()).filter(Boolean);
  console.log(`\n== control ${host}:${port} as ${acct.username} (FORCE.LOGIN=0) sources=${sources}`);

  const c = await conn(host, port, 'control');
  if (!(await login(c, acct, 1))) { console.log('login refused -> stop (try another ACC not in use on this CSP)'); c.s.destroy(); process.exit(3); }

  const perm = await cmd(c, { 5022: 'ListUserPermission', 5026: 2 }, 10000);
  const codes = new Set(); for (const p of perm.frames) for (const v of parse(p)['3'] || []) codes.add(v);
  console.log(`ListUserPermission -> 5001=${status(perm)} frames=${perm.frames.length} permissionCodes=${codes.size}`);
  for (const s of sources) console.log(`  source ${s} ${codes.has(s) ? 'IS' : 'is NOT'} in the permission list`);

  const routes = {};
  let tag = 10;
  for (const s of sources) {
    const r = await cmd(c, { 5022: 'GetPort', 5026: ++tag, 4: s });
    const o = r.frames.map(parse).find((x) => x['5001']) || {};
    routes[s] = { host: (o['13001'] || [])[0], port: (o['13101'] || [])[0] };
    console.log(`GetPort 4=${s} -> 5001=${status(r)} host=${routes[s].host} port=${routes[s].port}  raw=${r.frames.map(redact).join(' || ').slice(0, 300)}`);
  }
  c.s.destroy();

  if (process.env.SUB !== '1') { console.log('\n(SUB=1 not set: data-port subscribe test skipped)'); return; }
  for (const s of sources) {
    const rt = routes[s];
    if (!rt.port) { console.log(`source ${s}: no data port from GetPort, skip`); continue; }
    const dhost = rt.host || host;
    for (const verb of ['QueryDepthAndSubscribe', 'QuerySnapAndSubscribe']) {
      let d;
      try { d = await conn(dhost, Number(rt.port), `data ${s} ${verb}`); } catch (e) { console.log(`source ${s} ${verb}: connect ${dhost}:${rt.port} failed: ${e.message}`); continue; }
      if (await login(d, acct, 1)) {
        const r = await cmd(d, { 5022: verb, 5026: 2, 4: s }, 6000);
        await new Promise((z) => setTimeout(z, 4000));
        const data = d.frames.filter((p) => !/5001=/.test(p)).length;
        console.log(`source ${s} ${verb} @${dhost}:${rt.port} -> 5001=${status(r)} dataFramesIn4s=${data} first=${(r.frames[0] ? redact(r.frames[0]) : '').slice(0, 200)}`);
      }
      d.s.destroy();
      await new Promise((z) => setTimeout(z, 1500));
    }
  }
})().catch((e) => { console.log('ERROR', e.message); process.exit(1); });
