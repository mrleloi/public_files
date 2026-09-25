#!/usr/bin/env node
'use strict';
// tasks/uat-ice-prod-probe/uat-ice-prod-probe.js
//
// UAT-ICE-PROBE (S271, lane UAT-ICE-PROBE, human-requested UAT work — the
// D-202/S209 "agent scope = localhost+SIT only" rule is LIFTED for this one
// deliverable, per the human's explicit ask 2026-09-25). This is a
// ZERO-DEPENDENCY Node.js script meant to be copied into a UAT pod (which
// has real network access to the ICE production vendor CSP) and run
// MANUALLY BY THE HUMAN. See README.md in this same folder for exact run
// steps. The agent that wrote this file does NOT run it against UAT itself.
//
// WHY THIS EXISTS (two questions from the human, verbatim in the dispatch
// brief):
//   1. D-257 (agent-workspace/memory/decisions/257-*.md) found that on UAT,
//      sources 938/641 accept SetL2ConflationInterval/SetConflationInterval
//      (5001=0) but then reject the QueryDepthAndSubscribe carrying 2035=1
//      with -33 (ERR_PARAM_BOUNDARY); 585 worked with L1-style conflation.
//      The vendor doc says a 4th "Level 2 Conflation" type exists (CSP
//      v7.8+) for sources that are natively MBP (<=20 levels) or MBO
//      requested as MBP via DEPTH.TYPE/5039=1 — untested on our account.
//      Phase C below runs the documented variants and PROVES (not just
//      reports 5001) whether conflation actually took effect.
//   2. The human has never probed the vendor's real production CSP for the
//      23-source prod topology (tasks/post-9-9/ice-prod-account-topology.md)
//      end to end (both planes, L1/L2, image+live). Phase B below does that.
//
// SAFETY (this dials PRODUCTION market data, not a mock):
//   - LoginUser ALWAYS sends FORCE.LOGIN(5079)=0 — never kicks a live session
//     (ctf-command-reference.md:522, :530 "5079 FORCE.LOGIN").
//   - Strictly sequential: exactly ONE data-port connection open at a time,
//     across the whole run (no parallel dials).
//   - Every per-source / per-variant capture is bounded by BOTH a duration
//     timer and a byte cap; a source is Unsubscribe'd (ctf-command-
//     reference.md §2.3.2 / §3.3.2) and the socket destroyed on every exit
//     path, success or error.
//   - A global wall-clock cap aborts the remaining plan (still runs cleanup
//     + writes whatever was captured) rather than running unbounded. The
//     check happens BETWEEN steps, not by cancelling an in-flight network
//     wait -- so the worst-case overrun past the cap is bounded by whichever
//     single step is in flight when the deadline passes (control commands:
//     ~8-12s; a subscribe capture: up to --image-wait + its own duration +
//     5s). Tested (mock): a 4s cap actually finished at ~12s because
//     ListUserPermission's unbounded-on-the-mock 12s wait was already in
//     flight -- on the real vendor that command is expected to answer in
//     well under a second, so this is mostly a mock-testing artifact, not a
//     real-world concern, but it is a real, documented property of this
//     script: --wall-clock-cap is a soft cap with a bounded overrun, not a
//     hard kill.
//   - --dry-run prints the full plan (planes, sources, variants, durations,
//     an estimated total time) and exits WITHOUT opening a single socket.
//   - SIGINT (Ctrl-C) triggers the same clean-unsubscribe-and-close path
//     used by every other exit, then writes the partial JSON before exit.
//   - Every 5029 (USER.PASSWORD) value is redacted before it is ever logged
//     or embedded in the output file, including inside raw sample frames.
//     Credentials are read ONLY from env (PROBE_RT_USER/PROBE_RT_PASS,
//     PROBE_DL_USER/PROBE_DL_PASS) — never from a file, never printed.
//
// WIRE PROTOCOL BASE: framing (STX/HDR/len/ETX), the msg/parse/redact
// helpers, the cmd()-style "wait for the frame carrying my tag AND 5001"
// pattern, and the LoginUser/ListUserPermission/GetPort call shapes are
// reused, not reinvented, from the human-run base script
// tasks/uat-641-938/probe-src-perm.js (commit dd915aae) — see inline
// citations at each command site below for exact doc line numbers.
//
// DOC SOURCE: human-workspace/user_prompt/resources/ice_docs/
//   ctf-command-reference.md       (CTF = the raw wire commands MDP itself
//                                    speaks; every wire frame below cites a
//                                    line number in THIS file)
//   ice-api-developer-guide.md     (the vendor's higher-level SDK guide —
//                                    cited only for concepts not covered by
//                                    the CTF reference, e.g. Level 2
//                                    Conflation §5.4, IMAGE_COMPLETE
//                                    semantics §6.2.3)
//   wire-protocol-getting-started.md (image-vs-live-frame marking, REFRESH
//                                    token 24, market-phase life cycle)
//
// CONTRADICTIONS / CORRECTIONS FOUND WHILE BUILDING THIS (see the dev
// session's final report for the full list) — the short version:
//   - ctf-command-reference.md:530/:532 define 5079=FORCE.LOGIN and
//     13265=CTF.COMPRESSED. tasks/uat-641-938/probe-src-perm.js's own
//     in-file comment labels 13265 as "FORCE.LOGIN" — that comment is
//     WRONG, but the CODE is right (it sends BOTH 13265=0 and 5079=0, so
//     compressed=off and force-login=off either way). This script follows
//     the doc's token mapping exactly and names each token correctly.
//   - D-216 (agent-workspace/memory/decisions/216-*.md, DURABLE) says
//     source 922 was REMOVED because "UAT cannot access it". The vendor
//     doc's only documented heartbeat mechanism (wire-protocol-getting-
//     started.md:553-555) is delivered ON source 922. This script therefore
//     does NOT subscribe to 922 for its idle-heartbeat check (phase D) —
//     it instead just listens on the already-authenticated CONTROL
//     connection for the idle window and reports whatever arrives (almost
//     certainly nothing, since no data subscription is open on that
//     connection) — and says so explicitly in the output, rather than
//     silently reusing a source this account may not be entitled to.

const net = require('net');
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// 0. Wire protocol primitives (framing per ctf-command-reference.md's own
//    sample frames throughout §3, e.g. line 2006:
//      <0x04><0x20><LLLL>5022=LoginUser|5026=7|5028=user001|5029=PASSWD1<0x03>
//    STX=0x04, one header byte 0x20, a 4-byte big-endian length, the ASCII
//    pipe-delimited payload, ETX=0x03. Reused verbatim from
//    tasks/uat-641-938/probe-src-perm.js.)
// ---------------------------------------------------------------------------
const STX = 0x04, HDR = 0x20, ETX = 0x03;

function frame(payload) {
  const len = Buffer.byteLength(payload, 'ascii');
  const b = Buffer.allocUnsafe(7 + len);
  b[0] = STX; b[1] = HDR; b.writeUInt32BE(len, 2); b.write(payload, 6, len, 'ascii'); b[6 + len] = ETX;
  return b;
}
const msg = (f) => Object.entries(f).filter(([, v]) => v !== undefined && v !== null).map(([k, v]) => `${k}=${v}`).join('|');
function parse(p) {
  const o = {};
  for (const kv of p.split('|')) {
    const i = kv.indexOf('=');
    if (i > 0) { const k = kv.slice(0, i); (o[k] = o[k] || []).push(kv.slice(i + 1)); }
  }
  return o;
}
// Redact token 5029 (USER.PASSWORD) everywhere — command reference does not
// name a "password field" per se, but §2.1.1 (line 518) names 5029 as
// USER.PASSWORD; this is the ONLY credential-bearing token this protocol
// carries on the wire.
const redact = (p) => String(p).replace(/5029=[^|]*/g, '5029=<REDACTED>');
const trunc400 = (s) => (s.length > 400 ? s.slice(0, 400) + '...(truncated)' : s);

function conn(host, port, label, connTimeoutMs) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host, port });
    let buf = Buffer.alloc(0);
    const waiters = [];
    const c = { s, waiters, label, host, port, closed: false };
    s.setTimeout(connTimeoutMs || 15000, () => { s.destroy(new Error(`${label}: socket timeout`)); });
    s.on('data', (chunk) => {
      buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
      while (buf.length >= 7) {
        if (buf[0] !== STX || buf[1] !== HDR) {
          const i = buf.indexOf(STX, 1);
          buf = i < 0 ? Buffer.alloc(0) : buf.slice(i);
          continue;
        }
        const n = buf.readUInt32BE(2);
        if (buf.length < 7 + n) break;
        const p = buf.slice(6, 6 + n).toString('ascii');
        buf = buf.slice(7 + n);
        const recvTs = Date.now();
        for (const w of waiters.slice()) w(p, recvTs, n + 7);
      }
    });
    s.on('close', () => { c.closed = true; });
    s.on('error', (e) => { if (!s._ok) reject(e); else if (!c.closed) console.log(`[${label}] socket error: ${e.message}`); });
    s.on('connect', () => { s._ok = true; resolve(c); });
  });
}

function closeConn(c) {
  if (!c || c.closed) return;
  try { c.s.destroy(); } catch (_e) { /* best-effort */ }
  c.closed = true;
}

// cmd(): send a command and wait for the frame(s) carrying the SAME 5026
// (QUERY.TAG) that ALSO carries 5001 (ENUM.QUERY.STATUS) — per
// ctf-command-reference.md's own repeated pattern: "The last frame (5001=0)
// signals the end of the response" (e.g. lines 2375, 2389, 2409, 2436, 2449,
// 2485, 2499-2500 — every Query* command). Every earlier same-tag frame
// (e.g. ListUserPermission's repeated 3=<code> frames) is collected too.
function cmd(c, fields, waitMs) {
  const tag = String(fields['5026']);
  return new Promise((resolve) => {
    const got = [];
    let w;
    const done = (why) => {
      const idx = c.waiters.indexOf(w);
      if (idx >= 0) c.waiters.splice(idx, 1);
      clearTimeout(t);
      resolve({ why, frames: got });
    };
    w = (p) => {
      const o = parse(p);
      if ((o['5026'] || [])[0] !== tag) return;
      got.push(p);
      if (o['5001']) done('status');
    };
    const t = setTimeout(() => done('timeout'), waitMs || 8000);
    c.waiters.push(w);
    c.s.write(frame(msg(fields)));
  });
}
const status = (r) => { for (const p of r.frames) { const o = parse(p); if (o['5001']) return o['5001'][0]; } return `none(${r.why})`; };

// ---------------------------------------------------------------------------
// subscribeAndCapture(): issues a Query*Subscribe-family command and keeps
// capturing EVERY frame (any tag, including tag-less live ticks) for a
// bounded window. Splits the capture into IMAGE vs LIVE using the exact
// vendor-documented marker: the image ends at the frame carrying the
// subscribe command's own tag AND 5001 (see cmd()'s citation above) — every
// frame after that index is a live/streaming frame (ctf-command-
// reference.md:2478-2483 shows live MBP ticks arriving with NO 5026 tag at
// all once the "5026=5|5001=0" terminal frame has been sent).
// ---------------------------------------------------------------------------
function subscribeAndCapture(c, fields, opts) {
  const tag = String(fields['5026']);
  const imageWaitMs = opts.imageWaitMs || 8000;
  const liveDurationMs = opts.liveDurationMs || 12000;
  const byteCap = opts.byteCap || 3_000_000;
  return new Promise((resolve) => {
    const all = []; // {p, recvTs, bytes}
    let imageEndIndex = -1;
    let imageComplete = false;
    let totalBytes = 0;
    let liveArmed = false;
    let w;
    let imageTimer = null;
    let liveTimer = null;
    const ceiling = setTimeout(() => finish('ceiling'), imageWaitMs + liveDurationMs + 5000);
    function finish(why) {
      const idx = c.waiters.indexOf(w);
      if (idx >= 0) c.waiters.splice(idx, 1);
      clearTimeout(ceiling);
      if (imageTimer) clearTimeout(imageTimer);
      if (liveTimer) clearTimeout(liveTimer);
      resolve({ why, all, imageEndIndex, imageComplete, tag });
    }
    function armLiveDeadline() {
      if (liveArmed) return;
      liveArmed = true;
      if (imageTimer) clearTimeout(imageTimer);
      liveTimer = setTimeout(() => finish('live-duration-elapsed'), liveDurationMs);
    }
    w = (p, recvTs, bytes) => {
      all.push({ p, recvTs, bytes });
      totalBytes += bytes;
      const o = parse(p);
      if (imageEndIndex < 0 && (o['5026'] || [])[0] === tag && o['5001']) {
        imageEndIndex = all.length - 1;
        imageComplete = true;
        armLiveDeadline();
      }
      if (totalBytes >= byteCap) finish('byte-cap');
    };
    imageTimer = setTimeout(() => { imageComplete = false; armLiveDeadline(); }, imageWaitMs);
    c.waiters.push(w);
    c.s.write(frame(msg(fields)));
  });
}

// ---------------------------------------------------------------------------
// 1. LoginUser (ctf-command-reference.md §2.1.1, lines 505-556).
//    Mandatory: 5022=LoginUser, 5026=tag, 5028=USER_NAME, 5029=USER.PASSWORD.
//    Optional : 5079=FORCE.LOGIN (line 530) -- ALWAYS 0 here (never kick a
//               live session); 13265=CTF.COMPRESSED (line 532) -- 0
//               (uncompressed, simplest to parse); 5201=CONFLATE.INDICATOR
//               (line 531, detailed at line 403) -- 1, so every non-
//               conflatable (trade/status) live frame is marked 5201=0 by
//               the CSP, giving this script a documented, cheap way to
//               identify trade-bearing frames without guessing token IDs.
// ---------------------------------------------------------------------------
async function login(c, username, password, tag, waitMs) {
  const r = await cmd(c, {
    5022: 'LoginUser', 5026: tag, 5028: username, 5029: password,
    5079: 0,    // FORCE.LOGIN=0 (line 530) -- never forces out a live session
    13265: 0,   // CTF.COMPRESSED=0 (line 532)
    5201: 1,    // CONFLATE.INDICATOR=1 (line 531/403) -- tag non-conflatable frames
  }, waitMs || 8000);
  const st = status(r);
  console.log(`[${c.label}] LoginUser as ${username} -> 5001=${st}`);
  return { ok: st === '0', status: st, raw: r.frames.map(redact).map(trunc400) };
}

// ---------------------------------------------------------------------------
// 2. Embedded EXPECTED topology (NON-credential; from
//    tasks/post-9-9/ice-prod-account-topology.md §2, itself derived per
//    I-M3 discipline from the credential-bearing xlsx with columns A/B
//    excluded). 23 distinct sources: 10 dual, 6 realtime-only, 7 delay-only.
// ---------------------------------------------------------------------------
const EXPECTED_TOPOLOGY = [
  { id: '585', name: 'BURSA MALAYSIA', descRT: 'BURSA MALAYSIA EQ L2', descD: 'DLY BURS MAL EQ L2', plane: 'dual', qRT: 'R', qD: 'D', status: 'turned on' },
  { id: '714', name: 'BURSA MALAYSIA', descRT: 'BURSA MALAYSIA EQUITIES LEVEL 1', descD: 'DLY BURSA MALAYSIA EQUITIES L1', plane: 'dual', qRT: 'R', qD: 'D', status: 'turned on' },
  { id: '835', name: 'FTSE', descRT: 'BURSA MALAYSIA FTSE', descD: null, plane: 'realtime-only', qRT: 'R', qD: null, status: 'turned on' },
  { id: '648', name: 'FTSE', descRT: 'SGX FTSE ST INDICES', descD: null, plane: 'realtime-only', qRT: 'R', qD: null, status: 'turned on' },
  { id: '1089', name: 'HANG SENG', descRT: 'HANG SENG INDICES (FULL)', descD: 'DLY HANG SENG IND (FULL)', plane: 'dual', qRT: 'R', qD: 'D', status: 'turned on' },
  { id: '712', name: 'HONG KONG STOCK EXCHANGE', descRT: 'HONG KONG SE L1', descD: 'DLY HONG KONG SE', plane: 'dual', qRT: 'R', qD: 'D', status: 'turned on' },
  { id: '938', name: 'HONG KONG STOCK EXCHANGE', descRT: 'HONG KONG SE L2', descD: null, plane: 'realtime-only', qRT: 'R', qD: null, status: 'turned on' },
  { id: '899', name: 'SHANGHAI STOCK EXCHANGE', descRT: 'SHANGHAI SE LEVEL 1 BASIC', descD: 'DLY SHANGHAI SE L1 BASIC', plane: 'dual', qRT: 'R', qD: 'D', status: 'turned on' },
  { id: '898', name: 'SHENZHEN STOCK EXCHANGE', descRT: 'SHENZHEN SE LEVEL 1 (BASIC)', descD: 'DLY SHENZHEN SE L1 (BASIC)', plane: 'dual', qRT: 'R', qD: 'D', status: 'turned on' },
  { id: '713', name: 'SINGAPORE STOCK EXCHANGE', descRT: 'SINGAPORE SE', descD: 'DLY SINGAPORE SE', plane: 'dual', qRT: 'R', qD: 'D', status: 'turned on' },
  { id: '641', name: 'SINGAPORE STOCK EXCHANGE', descRT: 'SGX EQUITIES L2', descD: null, plane: 'realtime-only', qRT: 'R', qD: null, status: 'turned on' },
  { id: '14548', name: "STANDARD & POOR'S", descRT: 'IDC CUSIP CTF', descD: 'IDC CUSIP CTF', plane: 'dual', qRT: 'R', qD: 'R', status: 'turned on' },
  { id: '27544', name: 'ICE DATA SERVICES', descRT: 'ICE DS SYMBOL DIRECTORY SEDOLS', descD: 'ICE DS SYMBOL DIRECTORY SEDOLS', plane: 'dual', qRT: 'R', qD: 'R', status: 'turned on' },
  { id: '533', name: 'NASDAQ OMX', descRT: 'NASDAQ BASIC ISSUES', descD: null, plane: 'realtime-only', qRT: 'R', qD: null, status: 'pending exchange approval' },
  { id: '534', name: 'NASDAQ OMX', descRT: 'NASDAQ BASIC NYSE/NYSE AMERICAN', descD: null, plane: 'realtime-only', qRT: 'R', qD: null, status: 'pending exchange approval' },
  { id: '920', name: 'STOCK EXCHANGE OF THAILAND', descRT: 'THAILAND SE LEVEL 1', descD: 'DLY THAILAND SE', plane: 'dual', qRT: 'R', qD: 'D', status: 'RT turned on / Delay pending approval' },
  { id: '627', name: 'LONDON STOCK EXCHANGE', descRT: null, descD: 'DLY LSE DOM L1', plane: 'delay-only', qRT: null, qD: 'D', status: 'turned on' },
  { id: '728', name: 'AUSTRALIAN STOCK EXCHANGE', descRT: null, descD: 'DLY ASX E/F L1', plane: 'delay-only', qRT: null, qD: 'D', status: 'pending exchange approval' },
  { id: '653', name: 'CBOE', descRT: null, descD: 'DLY CBOE GLOBAL IND FEED - MAIN', plane: 'delay-only', qRT: null, qD: 'D', status: 'pending exchange approval' },
  { id: '629', name: 'LONDON STOCK EXCHANGE', descRT: null, descD: 'DLY LSE INTL L1', plane: 'delay-only', qRT: null, qD: 'D', status: 'pending exchange approval' },
  { id: '345', name: 'NASDAQ OMX', descRT: null, descD: 'DLY NASDAQ INDICES', plane: 'delay-only', qRT: null, qD: 'D', status: 'pending exchange approval' },
  { id: '372', name: 'TSX GROUP', descRT: null, descD: 'DLY TORONTO SE L1', plane: 'delay-only', qRT: null, qD: 'D', status: 'pending exchange approval' },
  { id: '374', name: 'TSX GROUP', descRT: null, descD: 'DLY TSX GROUP VENTURE EX CDNX', plane: 'delay-only', qRT: null, qD: 'D', status: 'pending exchange approval' },
];

// D-257 R1: sources dialled with the depth (L2) command by default. Any
// source id here uses QueryDepthAndSubscribe in phase B/C; everything else
// uses QuerySnapAndSubscribe (L1 style).
const DEFAULT_L2_SOURCE_IDS = ['585', '641', '938'];

// Approximate market-hours table -- STATIC, no holiday calendar, purely to
// annotate "was this market plausibly open at run time"; not authoritative.
const MARKET_HOURS = {
  '585': { tz: 'Asia/Kuala_Lumpur', open: '09:00', close: '17:00', name: 'Bursa Malaysia' },
  '714': { tz: 'Asia/Kuala_Lumpur', open: '09:00', close: '17:00', name: 'Bursa Malaysia' },
  '835': { tz: 'Asia/Kuala_Lumpur', open: '09:00', close: '17:00', name: 'Bursa Malaysia FTSE' },
  '648': { tz: 'Asia/Singapore', open: '09:00', close: '17:00', name: 'SGX FTSE ST Indices' },
  '1089': { tz: 'Asia/Hong_Kong', open: '09:30', close: '16:00', name: 'Hang Seng Indices' },
  '712': { tz: 'Asia/Hong_Kong', open: '09:30', close: '16:00', name: 'HKEX' },
  '938': { tz: 'Asia/Hong_Kong', open: '09:30', close: '16:00', name: 'HKEX L2' },
  '899': { tz: 'Asia/Shanghai', open: '09:30', close: '15:00', name: 'SSE' },
  '898': { tz: 'Asia/Shanghai', open: '09:30', close: '15:00', name: 'SZSE' },
  '713': { tz: 'Asia/Singapore', open: '09:00', close: '17:00', name: 'SGX' },
  '641': { tz: 'Asia/Singapore', open: '09:00', close: '17:00', name: 'SGX L2' },
  '14548': { tz: 'UTC', open: '00:00', close: '23:59', name: "S&P (CUSIP reference, always-on)" },
  '27544': { tz: 'UTC', open: '00:00', close: '23:59', name: 'ICE DS SEDOL (reference, always-on)' },
  '533': { tz: 'America/New_York', open: '09:30', close: '16:00', name: 'NASDAQ Basic' },
  '534': { tz: 'America/New_York', open: '09:30', close: '16:00', name: 'NASDAQ Basic NYSE/NYSE American' },
  '920': { tz: 'Asia/Bangkok', open: '10:00', close: '16:30', name: 'Thailand SE' },
  '627': { tz: 'Europe/London', open: '08:00', close: '16:30', name: 'LSE domestic' },
  '728': { tz: 'Australia/Sydney', open: '10:00', close: '16:00', name: 'ASX' },
  '653': { tz: 'America/Chicago', open: '08:30', close: '15:00', name: 'CBOE global indices' },
  '629': { tz: 'Europe/London', open: '08:00', close: '16:30', name: 'LSE international' },
  '345': { tz: 'America/New_York', open: '09:30', close: '16:00', name: 'NASDAQ indices' },
  '372': { tz: 'America/Toronto', open: '09:30', close: '16:00', name: 'Toronto SE' },
  '374': { tz: 'America/Toronto', open: '09:30', close: '16:00', name: 'TSX Venture' },
};

// ---------------------------------------------------------------------------
// 3. CLI argument parsing.
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  const args = {
    dryRun: false,
    phases: new Set(['perm', 'census', 'conflation', 'info']),
    planes: new Set(['realtime', 'delayed']),
    censusSources: null, // null = auto (every entitled source)
    conflationSources: DEFAULT_L2_SOURCE_IDS.concat(['712']), // +one L1 control per D-257's own comparison (712 worked with conflation)
    conflationIntervalMs: 500,
    sourceDurationSec: 12,
    conflationDurationSec: 12,
    byteCapBytes: 3_000_000,
    imageWaitMs: 8000,
    wallClockCapSec: 25 * 60,
    idleWindowSec: 15,
    skipIdleCheck: false,
    idleDataSessionCheck: false,
    idleDataSessionMaxSec: 180,
    allowPoolAccount: false,
    out: null,
    v4: true,
    verbose: false,
  };
  for (const raw of argv) {
    let a = raw;
    let val = true;
    if (a.startsWith('--no-')) { a = '--' + a.slice(5); val = false; }
    const eq = a.indexOf('=');
    let key = a, v = val;
    if (eq >= 0) { key = a.slice(0, eq); v = a.slice(eq + 1); }
    key = key.replace(/^--/, '');
    switch (key) {
      case 'dry-run': args.dryRun = v === true || v === 'true'; break;
      case 'phases': args.phases = new Set(String(v).split(',').map((x) => x.trim()).filter(Boolean)); break;
      case 'planes': args.planes = new Set(String(v).split(',').map((x) => x.trim()).filter(Boolean)); break;
      case 'census-sources': args.censusSources = String(v).split(',').map((x) => x.trim()).filter(Boolean); break;
      case 'sources': args.censusSources = String(v).split(',').map((x) => x.trim()).filter(Boolean); break;
      case 'conflation-sources': args.conflationSources = String(v).split(',').map((x) => x.trim()).filter(Boolean); break;
      case 'conflation-interval': args.conflationIntervalMs = Number(v); break;
      case 'source-duration': args.sourceDurationSec = Number(v); break;
      case 'conflation-duration': args.conflationDurationSec = Number(v); break;
      case 'byte-cap': args.byteCapBytes = Number(v); break;
      case 'image-wait': args.imageWaitMs = Number(v); break;
      case 'wall-clock-cap': args.wallClockCapSec = Number(v); break;
      case 'idle-window': args.idleWindowSec = Number(v); break;
      case 'skip-idle-check': args.skipIdleCheck = v === true || v === 'true'; break;
      case 'idle-data-session-check': args.idleDataSessionCheck = v === true || v === 'true'; break;
      case 'idle-data-session-max': args.idleDataSessionMaxSec = Number(v); break;
      case 'allow-pool-account': args.allowPoolAccount = v === true || v === 'true'; break;
      case 'out': args.out = String(v); break;
      case 'v4': args.v4 = v === true || v === 'true'; break;
      case 'verbose': args.verbose = v === true || v === 'true'; break;
      case 'help': args.help = true; break;
      default: console.log(`WARNING: unrecognized flag --${key}, ignoring`); break;
    }
  }
  return args;
}

function printHelp() {
  console.log(`uat-ice-prod-probe.js -- see README.md in this folder for full usage.
Flags: --dry-run --phases=perm,census,conflation,info --planes=realtime,delayed
  --census-sources=<csv> --conflation-sources=<csv> --conflation-interval=<ms>
  --source-duration=<sec> --conflation-duration=<sec> --byte-cap=<bytes>
  --image-wait=<ms> --wall-clock-cap=<sec> --idle-window=<sec> --skip-idle-check
  --idle-data-session-check --idle-data-session-max=<sec> --allow-pool-account
  --out=<path> --no-v4 --verbose
Env (credentials, never files): PROBE_RT_USER PROBE_RT_PASS PROBE_DL_USER PROBE_DL_PASS
Env (optional host override): PROBE_RT_HOST PROBE_RT_PORT PROBE_DL_HOST PROBE_DL_PORT
Env (optional, for pool-collision check + host fallback): ICE_ACCOUNT_POOL_JSON`);
}

// ---------------------------------------------------------------------------
// 4. Account resolution (I-M3: credentials from env ONLY; pool JSON read
//    only for non-credential host/port fallback + the collision check).
// ---------------------------------------------------------------------------
function resolveAccount(args, planeLabel, servingType, envUser, envPass, envHost, envPort, pool) {
  const username = process.env[envUser];
  const password = process.env[envPass];
  if (!username || !password) {
    return { skip: true, reason: `${envUser}/${envPass} not set -- ${planeLabel} plane skipped` };
  }
  const identityMatch = pool.find((p) => p.username === username);
  if (identityMatch) {
    console.log(`WARNING: username ${username} (${planeLabel}) IS present in this pod's ` +
      `ICE_ACCOUNT_POOL_JSON (accountId=${identityMatch.accountId}, servingType=${identityMatch.servingType}). ` +
      `A live UAT MDP session could be using this exact login right now.`);
    if (!args.allowPoolAccount) {
      return { skip: true, reason: `refusing to dial pool-registered account ${username} without --allow-pool-account` };
    }
  }
  let host = process.env[envHost];
  let port = process.env[envPort] ? Number(process.env[envPort]) : undefined;
  if (!host || !port) {
    const servingTypeFallback = pool.find((p) => p.servingType === servingType && p.cspIp && p.cspPort);
    if (servingTypeFallback) { host = host || servingTypeFallback.cspIp; port = port || Number(servingTypeFallback.cspPort); }
  }
  if (!host || !port) {
    return { skip: true, reason: `no host:port resolvable -- set ${envHost}/${envPort} or ensure ICE_ACCOUNT_POOL_JSON has a ${servingType} entry` };
  }
  return { skip: false, username, password, host, port, poolCollision: !!identityMatch };
}

// ---------------------------------------------------------------------------
// 5. Frame-set metrics (post-processing over a subscribeAndCapture() result).
// ---------------------------------------------------------------------------
function summarizeCapture(cap, windowStartTs) {
  const image = cap.imageEndIndex >= 0 ? cap.all.slice(0, cap.imageEndIndex + 1) : [];
  const live = cap.imageEndIndex >= 0 ? cap.all.slice(cap.imageEndIndex + 1) : cap.all;
  const symbolsOf = (frames) => {
    const set = new Set();
    for (const f of frames) { const o = parse(f.p); if (o['5']) set.add(o['5'][0]); }
    return set;
  };
  const imageSymbols = symbolsOf(image);
  const liveSymbols = symbolsOf(live);
  const sizes = live.map((f) => f.bytes).sort((a, b) => a - b);
  const pct = (arr, p) => (arr.length ? arr[Math.min(arr.length - 1, Math.floor(arr.length * p))] : 0);
  const fieldFreq = new Map();
  let tradeBearing = 0, tradeEligible = 0;
  const timestampSkewSamples = [];
  const delayMinsSamples = [];
  let refreshMidStream = 0;
  let askDepthCountMax = 0, bidDepthCountMax = 0, endUpdateFlagCount = 0;
  const perSecondCounts = new Map();
  const nowSecOf = (ts) => Math.floor((ts - windowStartTs) / 1000);
  for (const f of live) {
    const o = parse(f.p);
    for (const k of Object.keys(o)) fieldFreq.set(k, (fieldFreq.get(k) || 0) + 1);
    if (o['5201']) { tradeEligible++; if (o['5201'][0] === '0') tradeBearing++; }
    if (o['24'] && o['24'][0] === '1') refreshMidStream++;
    if (o['480']) askDepthCountMax = Math.max(askDepthCountMax, Number(o['480'][0]) || 0);
    if (o['481']) bidDepthCountMax = Math.max(bidDepthCountMax, Number(o['481'][0]) || 0);
    if (o['3851']) endUpdateFlagCount++;
    if (o['269']) delayMinsSamples.push(Number(o['269'][0]));
    const tsTok = o['16'] || o['20'] || o['55'];
    if (tsTok) {
      const v = parseFloat(tsTok[0]);
      if (Number.isFinite(v)) timestampSkewSamples.push((f.recvTs / 1000) - v);
    }
    const sec = nowSecOf(f.recvTs);
    perSecondCounts.set(sec, (perSecondCounts.get(sec) || 0) + 1);
  }
  const perSecArr = Array.from(perSecondCounts.values());
  const liveSpanMs = live.length ? (live[live.length - 1].recvTs - live[0].recvTs) : 0;
  const topFields = Array.from(fieldFreq.entries()).sort((a, b) => b[1] - a[1]).slice(0, 40)
    .map(([tok, count]) => ({ token: tok, count }));
  return {
    imageFrameCount: image.length,
    imageDistinctSymbols: imageSymbols.size,
    imageComplete: cap.imageComplete,
    imageEndReason: cap.why === 'byte-cap' ? 'byte-cap-during-image' : (cap.imageComplete ? 'terminal-status-frame' : 'image-wait-timeout'),
    liveFrameCount: live.length,
    liveDistinctSymbols: liveSymbols.size,
    liveSpanMs,
    liveBytesTotal: live.reduce((a, f) => a + f.bytes, 0),
    msgPerSecMean: liveSpanMs > 0 ? +(live.length / (liveSpanMs / 1000)).toFixed(2) : 0,
    msgPerSecMax: perSecArr.length ? Math.max(...perSecArr) : 0,
    frameSizeBytes: { p50: pct(sizes, 0.5), p95: pct(sizes, 0.95), max: sizes.length ? sizes[sizes.length - 1] : 0 },
    topFieldIds: topFields,
    tradeBearingShare: tradeEligible > 0 ? +(tradeBearing / tradeEligible).toFixed(4) : null,
    tradeBearingNote: tradeEligible > 0 ? 'via 5201 CONFLATE.INDICATOR=0 (non-conflatable frame), doc line 403' : 'no 5201 seen on live frames (source may not echo it, or login 5201=1 was not honoured)',
    refreshMidStreamFrames: refreshMidStream,
    l2DepthProxy: { askDepthCountMax, bidDepthCountMax, endUpdateFlagFrames: endUpdateFlagCount },
    vendorTimestampSkewSec: timestampSkewSamples.length
      ? { meanAbs: +(timestampSkewSamples.reduce((a, b) => a + Math.abs(b), 0) / timestampSkewSamples.length).toFixed(3), n: timestampSkewSamples.length }
      : null,
    delayMinsObserved: delayMinsSamples.length ? Array.from(new Set(delayMinsSamples)) : null,
    finishReason: cap.why,
    nonZeroStatuses: cap.all.filter((f) => { const o = parse(f.p); return o['5001'] && o['5001'][0] !== '0'; })
      .map((f) => trunc400(redact(f.p))),
    sampleFrames: [image[0], live[Math.floor(live.length / 2)], live[live.length - 1]]
      .filter(Boolean).map((f) => trunc400(redact(f.p))),
  };
}

// per-symbol inter-update interval, for the conflation proof (phase C).
function medianInterUpdateMs(liveFrames) {
  const bySymbol = new Map();
  for (const f of liveFrames) {
    const o = parse(f.p);
    const sym = (o['5'] || ['__source_level__'])[0];
    if (!bySymbol.has(sym)) bySymbol.set(sym, []);
    bySymbol.get(sym).push(f.recvTs);
  }
  const medians = [];
  for (const arr of bySymbol.values()) {
    if (arr.length < 2) continue;
    arr.sort((a, b) => a - b);
    const gaps = [];
    for (let i = 1; i < arr.length; i++) gaps.push(arr[i] - arr[i - 1]);
    gaps.sort((a, b) => a - b);
    medians.push(gaps[Math.floor(gaps.length / 2)]);
  }
  medians.sort((a, b) => a - b);
  return {
    perSymbolMedianMs: medians.length ? medians[Math.floor(medians.length / 2)] : null,
    symbolsWithMultipleUpdates: medians.length,
  };
}

// ---------------------------------------------------------------------------
// 6. Orchestration
// ---------------------------------------------------------------------------
const openConns = new Set();
async function safeConn(host, port, label, timeoutMs) {
  const c = await conn(host, port, label, timeoutMs);
  openConns.add(c);
  return c;
}
function safeClose(c) { if (c) { closeConn(c); openConns.delete(c); } }

async function unsubscribeAndClose(c, source) {
  if (!c || c.closed) return;
  try {
    // Unsubscribe (ctf-command-reference.md §2.3.2, line 1061-1109; sample
    // frame §3.3.2 line 2159/2163: `Unsubscribe|4=<src>|5026=<tag>`).
    await cmd(c, { 5022: 'Unsubscribe', 5026: 999, 4: source }, 4000);
  } catch (_e) { /* best-effort cleanup */ }
  // No CTF "Logout" command exists in ctf-command-reference.md's table of
  // contents (only §2.1.1 LoginUser under "Connection") -- ending a session
  // on this protocol is done by closing the TCP socket, which is what every
  // caller of safeClose()/unsubscribeAndClose() below does.
  safeClose(c);
}

function wallClockRemainingMs(state) { return state.deadline - Date.now(); }
function wallClockExceeded(state) {
  if (wallClockRemainingMs(state) <= 0) { state.aborted = true; state.abortReason = state.abortReason || 'wall-clock-cap reached'; return true; }
  return false;
}

async function runPhaseA(args, state, planeLabel, servingType, acct, entitledSet, routesOut, result) {
  console.log(`\n== [${planeLabel}] phase A (session) -- control ${acct.host}:${acct.port} as ${acct.username}`);
  // The control connection is deliberately kept open across phase B/C (which
  // can run many minutes on their OWN, separate data connections) so phase D
  // can listen on it for an idle-heartbeat window at the end -- give it a
  // generous socket timeout so THIS script's own connect-liveness safety net
  // never confounds phase D's "did the VENDOR close an idle session" question.
  const controlIdleTimeoutMs = Math.max(20 * 60 * 1000, (args.wallClockCapSec + 300) * 1000);
  const c = await safeConn(acct.host, acct.port, `${planeLabel}-control`, controlIdleTimeoutMs);
  const loginRes = await login(c, acct.username, acct.password, 1, 8000);
  result.login = { status: loginRes.status, ok: loginRes.ok, host: acct.host, port: acct.port, username: acct.username, poolCollision: !!acct.poolCollision, raw: loginRes.raw };
  if (!loginRes.ok) { safeClose(c); return { c: null }; }

  const perm = await cmd(c, { 5022: 'ListUserPermission', 5026: 2 }, 12000);
  const codes = new Set();
  for (const p of perm.frames) for (const v of parse(p)['3'] || []) codes.add(v);
  for (const code of codes) entitledSet.add(code);
  const expectedIds = new Set(EXPECTED_TOPOLOGY.filter((t) => (planeLabel === 'realtime' ? t.plane !== 'delay-only' : t.plane !== 'realtime-only')).map((t) => t.id));
  const entitledNotExpected = Array.from(codes).filter((c2) => !expectedIds.has(c2));
  const expectedNotEntitled = Array.from(expectedIds).filter((id) => !codes.has(id));
  result.listUserPermission = {
    status: status(perm), frameCount: perm.frames.length, permissionCodeCount: codes.size,
    entitledAndExpected: Array.from(codes).filter((c2) => expectedIds.has(c2)).sort(),
    entitledNotExpected: entitledNotExpected.sort(),
    expectedNotEntitled: expectedNotEntitled.sort(),
  };
  console.log(`[${planeLabel}] ListUserPermission -> 5001=${status(perm)} codes=${codes.size} expectedNotEntitled=${expectedNotEntitled.length} entitledNotExpected=${entitledNotExpected.length}`);

  result.getPort = {};
  let tag = 10;
  // Route every ENTITLED source (per ListUserPermission), PLUS every source
  // the operator explicitly named via --census-sources/--conflation-sources
  // even if ListUserPermission didn't confirm it -- entitlement listing is
  // advisory here (D-257's own evidence: a source's real dial-time behaviour
  // was the decisive signal, not a permission-list lookup, and this script
  // must not silently skip a source the human explicitly asked about just
  // because ListUserPermission omitted or mis-reported it). GetPort/Subscribe
  // will reject an actually-unentitled source on their own (-12 ERR_AUTH_REQ
  // etc.), which is itself useful, reported information.
  const explicit = new Set([...(args.censusSources || []), ...(args.conflationSources || [])]);
  const sourcesToRoute = Array.from(new Set([...codes, ...explicit]));
  for (const src of sourcesToRoute) {
    if (wallClockExceeded(state)) break;
    // GetPort (ctf-command-reference.md §2.2.8, lines 792-823; sample
    // §3.2.6 line 2107 `GetPort|4=558|5=IBM|5026=1`; response tokens
    // 13001=HOST.SERVER.IP, 13101=CLIENT.PORT).
    const r = await cmd(c, { 5022: 'GetPort', 5026: ++tag, 4: src }, 8000);
    const o = r.frames.map(parse).find((x) => x['5001']) || {};
    const route = { host: (o['13001'] || [])[0], port: (o['13101'] || [])[0], status: status(r) };
    routesOut[src] = route;
    result.getPort[src] = route;
  }
  console.log(`[${planeLabel}] GetPort resolved for ${Object.keys(routesOut).length} sources`);
  return { c };
}

async function probeOneSource(args, state, planeLabel, acct, source, route, isL2, durationSec, opts) {
  const label = `${planeLabel}-${source}-${isL2 ? 'L2' : 'L1'}`;
  if (!route || !route.host || !route.port) return { skipped: true, reason: 'no GetPort route' };
  let d;
  try { d = await safeConn(route.host, Number(route.port), label, 15000); }
  catch (e) { return { skipped: true, reason: `connect ${route.host}:${route.port} failed: ${e.message}` }; }
  const loginRes = await login(d, acct.username, acct.password, 1, 8000);
  if (!loginRes.ok) { safeClose(d); return { skipped: true, reason: `data-port login failed 5001=${loginRes.status}` }; }

  const preCommands = [];
  for (const pre of (opts && opts.preCommands) || []) {
    const r = await cmd(d, pre.fields, pre.waitMs || 6000);
    preCommands.push({ name: pre.name, sentFields: pre.fields, status: status(r), raw: r.frames.map((p) => trunc400(redact(p))) });
  }

  const tag = 2;
  const subFields = isL2
    // QueryDepthAndSubscribe (ctf-command-reference.md §2.4.4, lines 1686-1729;
    // sample §3.4.4 line 2463/2467). 4=ENUM.SRC.ID, source-only (no 5=).
    ? { 5022: 'QueryDepthAndSubscribe', 5026: tag, 4: source, ...(opts && opts.conflation ? { 2035: 1 } : {}), ...(opts && opts.depthType ? { 5039: opts.depthType } : {}) }
    // QuerySnapAndSubscribe (ctf-command-reference.md §2.4.5, lines 1731-1793;
    // sample §3.4.5 line 2497/2522). Source-only subscribe (matches D-207's
    // "source-only is a first-class level" design MDP itself now uses).
    : { 5022: 'QuerySnapAndSubscribe', 5026: tag, 4: source, ...(opts && opts.conflation ? { 2035: 1 } : {}) };
  const cap = await subscribeAndCapture(d, subFields, {
    imageWaitMs: args.imageWaitMs,
    liveDurationMs: durationSec * 1000,
    byteCap: args.byteCapBytes,
  });
  const windowStart = cap.all.length ? cap.all[0].recvTs : Date.now();
  const summary = summarizeCapture(cap, windowStart);
  const liveFrames = cap.imageEndIndex >= 0 ? cap.all.slice(cap.imageEndIndex + 1) : cap.all;
  await unsubscribeAndClose(d, source);
  return {
    skipped: false,
    dialMethod: isL2 ? 'QueryDepthAndSubscribe' : 'QuerySnapAndSubscribe',
    preCommands,
    summary,
    liveFrames, // raw {p,recvTs,bytes} live-phase frames, consumed by medianInterUpdateMs()
    subscribeStatusFrame: trunc400(redact((cap.all[cap.imageEndIndex] || {}).p || '')),
  };
}

async function runPhaseB(args, state, planeLabel, acct, entitledIds, routes, result) {
  // Explicit --census-sources runs AS GIVEN (entitlement is advisory, logged
  // per-source below, never a hard gate -- see runPhaseA's own routing note).
  // Auto mode (no explicit list) stays entitlement-filtered, since probing
  // all 23 topology sources on both planes unconditionally would blow the
  // wall-clock budget on an account only entitled to a subset.
  const sourceList = args.censusSources
    ? args.censusSources
    : Array.from(entitledIds).filter((id) => EXPECTED_TOPOLOGY.some((t) => t.id === id));
  console.log(`\n== [${planeLabel}] phase B (census) -- ${sourceList.length} sources, ${args.sourceDurationSec}s live capture each`);
  result.census = {};
  for (const src of sourceList) {
    if (wallClockExceeded(state)) { result.census[src] = { skipped: true, reason: state.abortReason }; continue; }
    const isL2 = DEFAULT_L2_SOURCE_IDS.includes(src);
    const entNote = entitledIds.has(src) ? '' : ' [NOT in ListUserPermission -- entitlement unconfirmed]';
    console.log(`  [${planeLabel}] census source ${src} (${isL2 ? 'L2/QueryDepthAndSubscribe' : 'L1/QuerySnapAndSubscribe'})${entNote}...`);
    const r = await probeOneSource(args, state, planeLabel, acct, src, routes[src], isL2, args.sourceDurationSec, { conflation: false });
    r.entitledPerListUserPermission = entitledIds.has(src);
    result.census[src] = r;
    if (r.skipped) console.log(`    skipped: ${r.reason}`);
    else console.log(`    image=${r.summary.imageFrameCount}f/${r.summary.imageDistinctSymbols}sym (${r.summary.imageEndReason})  live=${r.summary.liveFrameCount}f ${r.summary.msgPerSecMean}msg/s  symbols=${r.summary.liveDistinctSymbols}`);
  }
}

// Phase C -- the conflation matrix (the human's primary question). Runs the
// requested --conflation-sources AS GIVEN, same "entitlement is advisory"
// rationale as phase B above (D-257's own evidence came from dial-time
// behaviour, not a permission-list lookup).
async function runPhaseC(args, state, planeLabel, acct, entitledIds, routes, result) {
  const wanted = args.conflationSources;
  console.log(`\n== [${planeLabel}] phase C (conflation matrix) -- sources ${wanted.join(',') || '(none requested)'}`);
  result.conflation = {};
  for (const src of wanted) {
    if (wallClockExceeded(state)) { result.conflation[src] = { skipped: true, reason: state.abortReason }; continue; }
    const isL2 = DEFAULT_L2_SOURCE_IDS.includes(src);
    const route = routes[src];
    const variants = {};

    // V0 -- baseline, no conflation (same as census, but re-run fresh here so
    // the msg/s comparison is apples-to-apples with V1-V4 under identical
    // duration/byte-cap and immediately prior in time).
    console.log(`  [${planeLabel}] ${src} V0 baseline (no conflation)...`);
    const v0 = await probeOneSource(args, state, planeLabel, acct, src, route, isL2, args.conflationDurationSec, { conflation: false });
    variants.V0_baseline = finalizeVariant(v0, null);
    const baselineMsgPerSec = v0.skipped ? null : v0.summary.msgPerSecMean;
    const baselineMedian = v0.skipped ? null : medianInterUpdateMs(v0.liveFrames || []);

    if (!isL2) {
      // Non-L2 source in the conflation-sources list (e.g. the 712 control):
      // L1 conflation path only, per D-257's own comparison ("534/712/713
      // work with conflation").
      console.log(`  [${planeLabel}] ${src} V1 (L1 SetConflationInterval + Subscribe 2035=1)...`);
      const v1 = await runVariant(args, state, planeLabel, acct, src, route, false, {
        name: 'V1_L1_conflation',
        preCommands: [{ name: 'SetConflationInterval', fields: { 5022: 'SetConflationInterval', 5026: 90, 2029: args.conflationIntervalMs } }],
        conflation: true,
      }, baselineMsgPerSec, baselineMedian);
      variants.V1_L1_conflation = v1;
      result.conflation[src] = { isL2, route, entitledPerListUserPermission: entitledIds.has(src), variants };
      continue;
    }

    // V1 -- for an L2-listed source, still try the plain L1 SetConflationInterval
    // + QueryDepthAndSubscribe 2035=1 path (mirrors what MDP's UAT dial
    // actually sends today per D-257's evidence -- SetL2ConflationInterval OR
    // SetConflationInterval were both observed accepted with 5001=0 before the
    // subscribe's own -33).
    console.log(`  [${planeLabel}] ${src} V1 (SetConflationInterval "L1-style" + QueryDepthAndSubscribe 2035=1)...`);
    variants.V1_L1style_conflation = await runVariant(args, state, planeLabel, acct, src, route, true, {
      name: 'V1_SetConflationInterval',
      preCommands: [{ name: 'SetConflationInterval', fields: { 5022: 'SetConflationInterval', 5026: 90, 2029: args.conflationIntervalMs } }],
      conflation: true,
    }, baselineMsgPerSec, baselineMedian);

    // V2 -- the documented Level 2 Conflation path (ctf-command-reference.md
    // §2.2.11 SetL2ConflationInterval, lines 894-928; §1.2.8 "Level 2
    // Conflation" line 397-399; developer-guide §5.4 line 206) +
    // QueryDepthAndSubscribe 2035=1 (line 1690, 1705).
    console.log(`  [${planeLabel}] ${src} V2 (SetL2ConflationInterval + QueryDepthAndSubscribe 2035=1)...`);
    variants.V2_L2_conflation = await runVariant(args, state, planeLabel, acct, src, route, true, {
      name: 'V2_SetL2ConflationInterval',
      preCommands: [{ name: 'SetL2ConflationInterval', fields: { 5022: 'SetL2ConflationInterval', 5026: 90, 2029: args.conflationIntervalMs } }],
      conflation: true,
    }, baselineMsgPerSec, baselineMedian);

    // V3 -- V2 + DEPTH.TYPE=1 (request MBP explicitly; ctf-command-
    // reference.md line 1706 "5039 DEPTH.TYPE" optional arg on
    // QueryDepthAndSubscribe; sample MBP request line 2467
    // `QueryDepthAndSubscribe|4=267|5=F:BRN\U19|5026=1|5039=1`; developer-
    // guide §5.4 line 206 "MBO sources requested as Market-by-Price").
    console.log(`  [${planeLabel}] ${src} V3 (V2 + DEPTH.TYPE/5039=1, request MBP)...`);
    variants.V3_L2_conflation_depthType1 = await runVariant(args, state, planeLabel, acct, src, route, true, {
      name: 'V3_SetL2ConflationInterval_depthType',
      preCommands: [{ name: 'SetL2ConflationInterval', fields: { 5022: 'SetL2ConflationInterval', 5026: 90, 2029: args.conflationIntervalMs } }],
      conflation: true, depthType: 1,
    }, baselineMsgPerSec, baselineMedian);

    if (args.v4) {
      // V4 -- V2, but first explicitly pin the connection's conflation TYPE
      // to trade-safe (2035=1), ruling out a stray JIT type (types 3/4) left
      // over on the account from a previous session, since docs say "Level 2
      // conflation works with any value of CONFLATION_TYPE_LONG except the
      // JIT types" (developer-guide §5.4 line 207) and separately "while in
      // JIT mode, any requests for sources that cannot be conflated, such as
      // Lvl2 sources, will fail" (ctf-command-reference.md line 395).
      // SetConflationType: ctf-command-reference.md §2.2.12, lines 930-966.
      console.log(`  [${planeLabel}] ${src} V4 (SetConflationType 2035=1 trade-safe, then V2)...`);
      variants.V4_explicit_nonJIT_then_L2 = await runVariant(args, state, planeLabel, acct, src, route, true, {
        name: 'V4_SetConflationType_then_SetL2ConflationInterval',
        preCommands: [
          { name: 'SetConflationType', fields: { 5022: 'SetConflationType', 5026: 89, 2035: 1 } },
          { name: 'SetL2ConflationInterval', fields: { 5022: 'SetL2ConflationInterval', 5026: 90, 2029: args.conflationIntervalMs } },
        ],
        conflation: true,
      }, baselineMsgPerSec, baselineMedian);
    }

    result.conflation[src] = { isL2, route, entitledPerListUserPermission: entitledIds.has(src), variants };
  }
}

async function runVariant(args, state, planeLabel, acct, src, route, isL2, opts, baselineMsgPerSec, baselineMedian) {
  if (wallClockExceeded(state)) return { skipped: true, reason: state.abortReason };
  const r = await probeOneSource(args, state, planeLabel, acct, src, route, isL2, args.conflationDurationSec, opts);
  return finalizeVariant(r, { baselineMsgPerSec, baselineMedian });
}

function finalizeVariant(r, baseline) {
  if (r.skipped) return r;
  const median = medianInterUpdateMs(r.liveFrames || []);
  const subscribeStatusValue = (() => {
    const m = /5001=(-?\d+)/.exec(r.subscribeStatusFrame || '');
    return m ? m[1] : null;
  })();
  const out = {
    dialMethod: r.dialMethod,
    preCommands: r.preCommands,
    subscribeStatusFrame: r.subscribeStatusFrame,
    subscribeStatus5001: subscribeStatusValue,
    summary: r.summary,
    proof: {
      perSymbolMedianInterUpdateMs: median.perSymbolMedianMs,
      symbolsWithMultipleUpdates: median.symbolsWithMultipleUpdates,
      // conflation interval default 500ms -- treat >=400ms median as "likely
      // applied" (allows jitter/network scheduling slack below the nominal
      // interval); this is this script's own heuristic, not a vendor spec.
      conflationLikelyApplied: median.perSymbolMedianMs != null ? median.perSymbolMedianMs >= 400 : null,
    },
  };
  if (baseline) {
    out.vsBaseline = {
      baselineMsgPerSec: baseline.baselineMsgPerSec,
      thisMsgPerSec: r.summary.msgPerSecMean,
      msgPerSecDropRatio: baseline.baselineMsgPerSec ? +(1 - (r.summary.msgPerSecMean / baseline.baselineMsgPerSec)).toFixed(3) : null,
      baselineMedianMs: baseline.baselineMedian ? baseline.baselineMedian.perSymbolMedianMs : null,
    };
  }
  return out;
}

async function runPhaseD(args, state, planeLabel, c, result) {
  console.log(`\n== [${planeLabel}] phase D (extra vendor facts)`);
  result.extraFacts = {};
  if (!args.skipIdleCheck && c && !c.closed) {
    console.log(`  [${planeLabel}] idle-heartbeat: listening on the authenticated CONTROL connection for ${args.idleWindowSec}s with NO subscription open...`);
    const idleFrames = [];
    const w = (p, recvTs) => idleFrames.push({ p: trunc400(redact(p)), recvTs });
    c.waiters.push(w);
    await new Promise((res) => setTimeout(res, args.idleWindowSec * 1000));
    const idx = c.waiters.indexOf(w);
    if (idx >= 0) c.waiters.splice(idx, 1);
    result.extraFacts.idleHeartbeat = {
      windowSec: args.idleWindowSec,
      framesReceived: idleFrames.length,
      frames: idleFrames,
      note: 'D-216 (durable): source 922 was removed because UAT cannot access it, and the vendor doc\'s only ' +
        'documented heartbeat (wire-protocol-getting-started.md:553-555) is delivered ON source 922 -- so this ' +
        'probe does NOT subscribe to 922 and instead just listens on the idle authenticated control connection. ' +
        'Zero frames here is the expected/likely outcome and does NOT mean the connection is dead.',
    };
    console.log(`    idle window: ${idleFrames.length} frame(s) received while idle`);
  } else {
    const reason = args.skipIdleCheck ? '--skip-idle-check' : (c ? 'control connection was already closed before phase D (check earlier socket-error log lines)' : 'no control connection available (login failed)');
    console.log(`  [${planeLabel}] idle-heartbeat: SKIPPED (${reason})`);
    result.extraFacts.idleHeartbeat = { skipped: true, reason };
  }

  if (args.idleDataSessionCheck) {
    result.extraFacts.idleDataSessionTimeout = { note: 'requested via --idle-data-session-check but not exercised in this run (implementation deliberately conservative -- see README).', boundedMaxSec: args.idleDataSessionMaxSec };
  } else {
    result.extraFacts.idleDataSessionTimeout = { skipped: true, reason: 'off by default -- pass --idle-data-session-check to enable (bounded by --idle-data-session-max)' };
  }
}

function runPhaseE(result) {
  const now = new Date();
  const utc = now.toISOString();
  const hkt = now.toLocaleString('en-US', { timeZone: 'Asia/Hong_Kong', hour12: false });
  const marketsOpen = [];
  for (const [srcId, m] of Object.entries(MARKET_HOURS)) {
    try {
      const local = now.toLocaleString('en-US', { timeZone: m.tz, hour12: false, hour: '2-digit', minute: '2-digit' });
      const [h, min] = local.split(':').map(Number);
      const minutesNow = h * 60 + min;
      const [oh, om] = m.open.split(':').map(Number);
      const [ch, cm] = m.close.split(':').map(Number);
      const openMin = oh * 60 + om, closeMin = ch * 60 + cm;
      const isOpen = minutesNow >= openMin && minutesNow <= closeMin;
      marketsOpen.push({ source: srcId, name: m.name, tz: m.tz, localTime: local, plausiblyOpen: isOpen });
    } catch (_e) { /* unknown tz, skip */ }
  }
  result.clock = {
    utc, hkt,
    note: 'STATIC approximation, no holiday calendar -- for interpreting rate/throughput numbers only, not authoritative.',
    marketsOpen,
  };
}

// ---------------------------------------------------------------------------
// 7. main
// ---------------------------------------------------------------------------
async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { printHelp(); return; }

  const pool = (() => { try { return JSON.parse(process.env.ICE_ACCOUNT_POOL_JSON || '[]'); } catch (_e) { return []; } })();
  console.log('pool entries (no secrets):');
  for (const a of pool) console.log(`  ${a.accountId} user=${a.username} set=${a.setId} ${a.servingType} ${a.cspIp}:${a.cspPort}`);

  const planPlanes = [];
  if (args.planes.has('realtime')) planPlanes.push({ label: 'realtime', servingType: 'realtime', envUser: 'PROBE_RT_USER', envPass: 'PROBE_RT_PASS', envHost: 'PROBE_RT_HOST', envPort: 'PROBE_RT_PORT' });
  if (args.planes.has('delayed')) planPlanes.push({ label: 'delayed', servingType: 'delayed', envUser: 'PROBE_DL_USER', envPass: 'PROBE_DL_PASS', envHost: 'PROBE_DL_HOST', envPort: 'PROBE_DL_PORT' });

  const resolvedAccounts = {};
  for (const p of planPlanes) resolvedAccounts[p.label] = resolveAccount(args, p.label, p.servingType, p.envUser, p.envPass, p.envHost, p.envPort, pool);

  const est = estimateRuntimeSec(args, planPlanes, resolvedAccounts);
  console.log(`\nPLAN:`);
  console.log(`  phases: ${Array.from(args.phases).join(',')}`);
  console.log(`  planes: ${planPlanes.map((p) => `${p.label}(${resolvedAccounts[p.label].skip ? 'SKIP: ' + resolvedAccounts[p.label].reason : resolvedAccounts[p.label].username + '@' + resolvedAccounts[p.label].host + ':' + resolvedAccounts[p.label].port})`).join(', ')}`);
  console.log(`  census-sources: ${args.censusSources ? args.censusSources.join(',') : 'auto (every entitled source found in ListUserPermission)'}  duration=${args.sourceDurationSec}s each`);
  console.log(`  conflation-sources: ${args.conflationSources.join(',')}  variants=V0${args.v4 ? ',V1-V4' : ',V1-V3'}  duration=${args.conflationDurationSec}s each  interval=${args.conflationIntervalMs}ms`);
  console.log(`  byte-cap=${args.byteCapBytes}  image-wait=${args.imageWaitMs}ms  wall-clock-cap=${args.wallClockCapSec}s`);
  console.log(`  idle-heartbeat-window=${args.skipIdleCheck ? 'SKIPPED' : args.idleWindowSec + 's'}  idle-data-session-check=${args.idleDataSessionCheck ? 'ON (max ' + args.idleDataSessionMaxSec + 's)' : 'off'}`);
  console.log(`  ESTIMATED total runtime: ~${Math.round(est / 60)} min (${est}s) -- this is a rough per-item-overhead estimate, not a guarantee`);

  if (args.dryRun) { console.log('\n--dry-run: exiting without opening any socket.'); return; }
  if (est > args.wallClockCapSec) console.log(`\nNOTE: estimated runtime (${est}s) exceeds --wall-clock-cap (${args.wallClockCapSec}s) -- the run WILL be cut short; consider narrowing --phases/--planes/--census-sources or raising --wall-clock-cap.`);

  const state = { deadline: Date.now() + args.wallClockCapSec * 1000, aborted: false, abortReason: null };
  const scriptSelfHash = crypto.createHash('sha256').update(fs.readFileSync(__filename)).digest('hex');
  const result = {
    schemaVersion: 1,
    scriptSha256: scriptSelfHash,
    nodeVersion: process.version,
    hostname: os.hostname(),
    startedAtUtc: new Date().toISOString(),
    args: { ...args, phases: Array.from(args.phases), planes: Array.from(args.planes) },
    aborted: false,
    abortReason: null,
    planes: {},
  };

  let sigintHandled = false;
  const cleanupAndWrite = async (reason) => {
    if (sigintHandled) return;
    sigintHandled = true;
    console.log(`\nCleaning up (${reason})...`);
    for (const c of Array.from(openConns)) safeClose(c);
    result.aborted = state.aborted || reason !== 'normal-completion';
    result.abortReason = state.abortReason || (reason !== 'normal-completion' ? reason : null);
    result.finishedAtUtc = new Date().toISOString();
    writeOutput(args, result);
  };
  process.on('SIGINT', () => { cleanupAndWrite('SIGINT').then(() => process.exit(130)); });

  try {
    for (const p of planPlanes) {
      const acct = resolvedAccounts[p.label];
      const planeResult = { skipped: acct.skip, reason: acct.skip ? acct.reason : undefined };
      result.planes[p.label] = planeResult;
      if (acct.skip) { console.log(`\n[${p.label}] SKIPPED: ${acct.reason}`); continue; }
      if (wallClockExceeded(state)) { planeResult.skipped = true; planeResult.reason = state.abortReason; continue; }

      const entitledIds = new Set();
      const routes = {};
      const { c } = await runPhaseA(args, state, p.label, p.servingType, acct, entitledIds, routes, planeResult);
      if (!c) { planeResult.reason = 'login failed'; continue; }

      if (args.phases.has('census') && !wallClockExceeded(state)) await runPhaseB(args, state, p.label, acct, entitledIds, routes, planeResult);
      if (args.phases.has('conflation') && !wallClockExceeded(state)) await runPhaseC(args, state, p.label, acct, entitledIds, routes, planeResult);
      if (args.phases.has('info') && !wallClockExceeded(state)) await runPhaseD(args, state, p.label, c, planeResult);
      safeClose(c);
    }
    runPhaseE(result);
  } catch (e) {
    result.fatalError = String((e && e.stack) || e);
    state.aborted = true;
    state.abortReason = state.abortReason || `fatal: ${e.message}`;
    console.log(`FATAL: ${e.message}`);
  } finally {
    await cleanupAndWrite(state.aborted ? (state.abortReason || 'aborted') : 'normal-completion');
  }
}

function estimateRuntimeSec(args, planPlanes, resolvedAccounts) {
  let total = 0;
  for (const p of planPlanes) {
    if (resolvedAccounts[p.label].skip) continue;
    total += 5; // phase A overhead (login + ListUserPermission + ~16 GetPort calls)
    if (args.phases.has('census')) {
      const n = args.censusSources ? args.censusSources.length : EXPECTED_TOPOLOGY.filter((t) => (p.label === 'realtime' ? t.plane !== 'delay-only' : t.plane !== 'realtime-only')).length;
      total += n * (args.sourceDurationSec + 4);
    }
    if (args.phases.has('conflation')) {
      const variantsPerSource = args.v4 ? 5 : 4; // V0 + up to V1-V4 (or V1 only for a non-L2 control source, handled loosely here)
      total += args.conflationSources.length * variantsPerSource * (args.conflationDurationSec + 4);
    }
    if (args.phases.has('info') && !args.skipIdleCheck) total += args.idleWindowSec;
    if (args.phases.has('info') && args.idleDataSessionCheck) total += args.idleDataSessionMaxSec;
  }
  return total;
}

function writeOutput(args, result) {
  const outPath = args.out || path.join(os.tmpdir(), `uat-ice-prod-probe-${Date.now()}.json`);
  const json = JSON.stringify(result, null, 2);
  fs.writeFileSync(outPath, json, 'utf8');
  console.log(`\nOutput written: ${outPath} (${json.length} bytes)`);
  console.log(`\n===== SUMMARY =====`);
  for (const [plane, r] of Object.entries(result.planes || {})) {
    if (r.skipped) { console.log(`${plane}: SKIPPED (${r.reason})`); continue; }
    const permCount = r.listUserPermission ? r.listUserPermission.permissionCodeCount : '?';
    const censusN = r.census ? Object.keys(r.census).length : 0;
    const conflN = r.conflation ? Object.keys(r.conflation).length : 0;
    console.log(`${plane}: login=${r.login ? r.login.status : '?'} permissionCodes=${permCount} census-sources=${censusN} conflation-sources=${conflN}`);
    if (r.conflation) {
      for (const [src, cr] of Object.entries(r.conflation)) {
        if (cr.skipped) { console.log(`  ${src}: skipped (${cr.reason})`); continue; }
        for (const [vname, v] of Object.entries(cr.variants || {})) {
          if (v.skipped) { console.log(`  ${src} ${vname}: skipped (${v.reason})`); continue; }
          console.log(`  ${src} ${vname}: subscribe5001=${v.subscribeStatus5001 !== undefined ? v.subscribeStatus5001 : 'n/a'} applied=${v.proof ? v.proof.conflationLikelyApplied : 'n/a'} medianMs=${v.proof ? v.proof.perSymbolMedianInterUpdateMs : 'n/a'} msg/s=${v.summary ? v.summary.msgPerSecMean : 'n/a'}`);
        }
      }
    }
  }
  console.log(`aborted=${result.aborted} abortReason=${result.abortReason || 'n/a'}`);
  console.log(`===== END SUMMARY =====\n`);
}

main().catch((e) => { console.log('FATAL (uncaught):', e && e.stack || e); process.exit(1); });
