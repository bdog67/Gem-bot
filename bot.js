#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════
//  GEM HUNTER — Secure 24/7 Server Bot v2
//  - AES-256-GCM encrypted wallet (key never in plain text)
//  - PIN-protected dashboard
//  - Active Jupiter trading from bot wallet
//  - Rate-limited endpoints, session tokens
//  - No private key ever logged or exposed via API
//  Usage: node bot.js
//  Dashboard: http://localhost:3000
// ═══════════════════════════════════════════════════════════════
'use strict';
const fs     = require('fs');
const path   = require('path');
const http   = require('http');
const https  = require('https');
const crypto = require('crypto');

// ── Config (Railway environment variables) ───────────────
const C = {
  CLAUDE_KEY : process.env.CLAUDE_API_KEY   || '',
  MODE       : process.env.MODE             || 'paper',
  INTERVAL   : +(process.env.SCAN_INTERVAL  || 20),
  POS_SOL    : +(process.env.POS_SIZE_SOL   || 0.05),
  MAX_POS    : +(process.env.MAX_POSITIONS   || 5),
  MIN_SCORE  : +(process.env.MIN_SCORE      || 62),
  STOP_PCT   : +(process.env.STOP_LOSS_PCT  || 45),
  TRAIL_PCT  : +(process.env.TRAIL_STOP_PCT || 35),
  MAX_HOLD   : +(process.env.MAX_HOLD_HOURS || 168),
  MIN_MC     : +(process.env.MIN_MC         || 15000),
  MAX_MC     : +(process.env.MAX_MC         || 300000),
  MAX_RISK   : +(process.env.MAX_RISK       || 40),
  PORT       : +(process.env.PORT           || 3000),
  DATA       : process.env.DATA_DIR         || './data',
  START_BAL  : +(process.env.PAPER_BAL      || 100),
  ANTIRUG    : process.env.ANTIRUG          !== 'false',
  RPC        : process.env.RPC_URL          || 'https://api.mainnet-beta.solana.com',
  // DASHBOARD_PIN: set this in Railway variables to protect your dashboard
  // If not set, dashboard is open (fine for testing, set it for real money)
  DASH_PIN   : process.env.DASHBOARD_PIN    || '',
};

const JUP_Q   = 'https://quote-api.jup.ag/v6/quote';
const JUP_SWAP= 'https://quote-api.jup.ag/v6/swap';
const DEX_API = 'https://api.dexscreener.com';
const CLAUDE  = 'https://api.anthropic.com/v1/messages';
const SOL_MINT= 'So11111111111111111111111111111111111111112';
const MODEL   = 'claude-sonnet-4-6';
const LAMPORTS= 1e9;
const B58_CHARS='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

// ── Data directory ────────────────────────────────────────
if (!fs.existsSync(C.DATA)) fs.mkdirSync(C.DATA, {recursive:true});
const WALLET_F  = path.join(C.DATA, 'wallet.enc');   // AES-256-GCM encrypted
const BRAIN_F   = path.join(C.DATA, 'brain.json');
const TRADES_F  = path.join(C.DATA, 'trades.json');
const LOG_F     = path.join(C.DATA, 'bot.log');

// ═══════════════════════════════════════════════════════════
//  SECURITY — AES-256-GCM wallet encryption
//  Private key is NEVER stored in plain text anywhere
//  NEVER logged, never in API responses, never in env vars
// ═══════════════════════════════════════════════════════════
const PBKDF2_ITER = 310000; // NIST recommended minimum

function encryptWallet(secretKeyBytes, pin) {
  const salt = crypto.randomBytes(32);
  const iv   = crypto.randomBytes(12);
  const key  = crypto.pbkdf2Sync(pin, salt, PBKDF2_ITER, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct   = Buffer.concat([cipher.update(secretKeyBytes), cipher.final()]);
  const tag  = cipher.getAuthTag();
  // Format: salt(32) + iv(12) + tag(16) + ciphertext
  const packed = Buffer.concat([salt, iv, tag, ct]);
  return packed.toString('base64');
}

function decryptWallet(b64, pin) {
  const packed = Buffer.from(b64, 'base64');
  const salt   = packed.slice(0, 32);
  const iv     = packed.slice(32, 44);
  const tag    = packed.slice(44, 60);
  const ct     = packed.slice(60);
  const key    = crypto.pbkdf2Sync(pin, salt, PBKDF2_ITER, 32, 'sha256');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new Error('Wrong PIN or corrupted wallet file');
  }
}

// ── Base58 ────────────────────────────────────────────────
function b58enc(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let s = '';
  while (n > 0n) { const r = n % 58n; s = B58_CHARS[Number(r)] + s; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; s = '1' + s; }
  return s;
}
function b58dec(str) {
  let n = 0n;
  for (const c of str) {
    const i = B58_CHARS.indexOf(c);
    if (i < 0) throw new Error('Invalid base58 character: ' + c);
    n = n * 58n + BigInt(i);
  }
  const bytes = [];
  while (n > 0n) { bytes.unshift(Number(n & 0xffn)); n >>= 8n; }
  for (const c of str) { if (c !== '1') break; bytes.unshift(0); }
  return Buffer.from(bytes);
}

// ── Wallet state (in-memory only, never persisted plain) ─
let walletLoaded  = false;
let walletPubkey  = '';   // public key as base58 string (safe to display)
let walletSK      = null; // 64-byte secret key — only in RAM, never logged
let solBalance    = 0;

// ── Dashboard session tokens (simple but effective) ──────
const sessions   = new Set();
const SESSION_TTL= 4 * 3600 * 1000; // 4 hours
const sessionExp = new Map();
function createSession() {
  const tok = crypto.randomBytes(24).toString('hex');
  sessions.add(tok);
  sessionExp.set(tok, Date.now() + SESSION_TTL);
  return tok;
}
function validSession(tok) {
  if (!tok || !sessions.has(tok)) return false;
  if (Date.now() > (sessionExp.get(tok)||0)) { sessions.delete(tok); return false; }
  return true;
}

// ── Rate limiting (protect dashboard from brute force) ───
const rateLimits = new Map();
function rateLimit(ip, maxReqs=10, windowMs=60000) {
  const now = Date.now();
  const entry = rateLimits.get(ip) || { count:0, reset:now+windowMs };
  if (now > entry.reset) { entry.count=0; entry.reset=now+windowMs; }
  entry.count++;
  rateLimits.set(ip, entry);
  return entry.count > maxReqs;
}

// ═══════════════════════════════════════════════════════════
//  STATE
// ═══════════════════════════════════════════════════════════
let solPrice=170, running=false;
let paperBal=C.START_BAL, positions=[], trades=loadJ(TRADES_F)||[];
let wins=0, losses=0, streak=0, cycle=0, startedAt=null;
let regime='neutral', analyzing=new Set(), pyrs={}, nextTimer=null;
const logs=[];
let lastScanStats={total:0,sources:0,filtered:0,runners:[]};

trades.forEach(t => t.pnl>0 ? wins++ : losses++);

// ═══════════════════════════════════════════════════════════
//  LOGGING (never logs private key or full secret)
// ═══════════════════════════════════════════════════════════
function log(type, label, detail='') {
  // Security: block any accidental private key leakage
  if (walletSK) {
    const skHex = Buffer.from(walletSK).toString('hex');
    if (detail.includes(skHex) || label.includes(skHex)) {
      detail = '[REDACTED — private key]';
    }
  }
  const ts   = new Date().toISOString();
  const line = `[${ts}] [${type.toUpperCase()}] ${label}${detail?' — '+detail:''}`;
  console.log(line);
  try { fs.appendFileSync(LOG_F, line + '\n'); } catch {}
  logs.unshift({ts, type, label, detail});
  if (logs.length > 200) logs.pop();
}

// ═══════════════════════════════════════════════════════════
//  PERSISTENCE
// ═══════════════════════════════════════════════════════════
function loadJ(file) { try { return JSON.parse(fs.readFileSync(file,'utf8')); } catch { return null; } }
function saveJ(file, data) { try { fs.writeFileSync(file, JSON.stringify(data, null, 2)); } catch(e) { log('warn','SAVE',e.message); } }

// ═══════════════════════════════════════════════════════════
//  BRAIN (self-learning)
// ═══════════════════════════════════════════════════════════
let brain = loadJ(BRAIN_F) || {
  totalTrades:0, lifetimeWins:0, lifetimeLosses:0, lifetimePnl:0, epoch:0,
  patterns:{ winBSR:[], loseBSR:[], winScore:[], loseScore:[], winAge:[], loseAge:[], winHold:[], loseHold:[] },
  evolvedParams:{ minBSR:1.1, minScore:C.MIN_SCORE, kellyFraction:0.5 },
  insights:[], hallOfFame:[], hallOfShame:[]
};
function saveBrain() { saveJ(BRAIN_F, brain); }
function avg(a) { return a.length ? a.reduce((s,v)=>s+v,0)/a.length : null; }

function learnFromTrade(trade, meta) {
  if (!meta) return;
  const win=trade.pnl>0, pre=win?'win':'lose';
  const push=(arr,v)=>{arr.push(v);if(arr.length>100)arr.shift();};
  push(brain.patterns[pre+'BSR'],   meta.bsr   || 1);
  push(brain.patterns[pre+'Score'], meta.score || 50);
  push(brain.patterns[pre+'Age'],   meta.age   || 48);
  if (trade.closedAt && trade.openedAt)
    push(brain.patterns[pre+'Hold'], (trade.closedAt-trade.openedAt)/3600000);
  brain.totalTrades++; brain.lifetimePnl += trade.pnl||0;
  if (win) brain.lifetimeWins++; else brain.lifetimeLosses++;
  const sum={token:trade.token,pct:trade.pct||0,pnl:trade.pnl||0,bsr:meta.bsr,score:meta.score};
  if (win) { brain.hallOfFame.push(sum); brain.hallOfFame.sort((a,b)=>b.pnl-a.pnl); if(brain.hallOfFame.length>5)brain.hallOfFame.pop(); }
  else     { brain.hallOfShame.push(sum); brain.hallOfShame.sort((a,b)=>a.pnl-b.pnl); if(brain.hallOfShame.length>5)brain.hallOfShame.pop(); }
  if (brain.totalTrades % 5 === 0) evolveParams();
  saveBrain();
}

function evolveParams() {
  const p=brain.patterns, ep=brain.evolvedParams;
  if (brain.totalTrades<4) return;
  const wB=avg(p.winBSR), lB=avg(p.loseBSR);
  if (wB&&lB) ep.minBSR=Math.max(1.0,Math.min(3.0,wB*0.7+ep.minBSR*0.3));
  const wS=avg(p.winScore);
  if (wS) ep.minScore=Math.round(Math.max(45,Math.min(80,wS*0.75+ep.minScore*0.25)));
  const wr=brain.totalTrades>0?brain.lifetimeWins/brain.totalTrades:0.45;
  ep.kellyFraction=Math.max(0.25,Math.min(0.75,0.35+wr*0.4));
  brain.epoch++;
  log('info',`🧬 EPOCH ${brain.epoch}`,`BSR→${ep.minBSR.toFixed(2)} score→${ep.minScore} kelly→${(ep.kellyFraction*100).toFixed(0)}%`);
  saveBrain();
}

function learnedCtx() {
  const p=brain.patterns, ep=brain.evolvedParams;
  if (brain.totalTrades<2) return 'No history yet.';
  const lines=[`BRAIN: ${brain.totalTrades} trades, P&L $${brain.lifetimePnl.toFixed(2)}`];
  if (p.winBSR.length) lines.push(`Win BSR ${avg(p.winBSR).toFixed(2)}x vs lose ${avg(p.loseBSR)?.toFixed(2)||'?'}x → min ${ep.minBSR.toFixed(2)}x`);
  if (p.winScore.length) lines.push(`Win score ${avg(p.winScore).toFixed(0)} vs lose ${avg(p.loseScore)?.toFixed(0)||'?'} → threshold ${ep.minScore}`);
  if (brain.insights.length) lines.push(`Insight: "${brain.insights[0].text.slice(0,120)}"`);
  return lines.join('\n');
}

// ═══════════════════════════════════════════════════════════
//  HTTP HELPERS
// ═══════════════════════════════════════════════════════════
function get(url, hdrs={}) {
  return new Promise((res,rej) => {
    const req = https.get(url, {headers:{'Accept':'application/json',...hdrs}}, r => {
      let d=''; r.on('data',c=>d+=c);
      r.on('end',()=>{try{res(JSON.parse(d));}catch(e){rej(new Error('parse:'+d.slice(0,60)));}});
    });
    req.on('error',rej);
    req.setTimeout(15000,()=>{req.destroy();rej(new Error('timeout'));});
  });
}

function post(url, body, hdrs={}) {
  return new Promise((res,rej) => {
    const s=JSON.stringify(body), u=new URL(url);
    const req=https.request({hostname:u.hostname,path:u.pathname+u.search,method:'POST',
      headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(s),...hdrs}},r=>{
      let d=''; r.on('data',c=>d+=c);
      r.on('end',()=>{try{res(JSON.parse(d));}catch(e){rej(new Error('parse:'+d.slice(0,60)));}});
    });
    req.on('error',rej); req.setTimeout(30000,()=>{req.destroy();rej(new Error('timeout'));});
    req.write(s); req.end();
  });
}

function claudeCall(prompt, maxT=200) {
  if (!C.CLAUDE_KEY) return Promise.resolve(null);
  return post(CLAUDE,{model:MODEL,max_tokens:maxT,messages:[{role:'user',content:prompt}]},
    {'x-api-key':C.CLAUDE_KEY,'anthropic-version':'2023-06-01'});
}

function rpc(method, params) {
  return post(C.RPC,{jsonrpc:'2.0',id:1,method,params})
    .then(d=>{if(d.error)throw new Error(d.error.message);return d.result;});
}

// ═══════════════════════════════════════════════════════════
//  WALLET OPERATIONS
// ═══════════════════════════════════════════════════════════
async function walletCreate(pin) {
  // Generate random 32-byte seed
  const seed = crypto.randomBytes(32);
  // Derive public key via SHA-256 (same as browser bot)
  const pub  = crypto.createHash('sha256').update(seed).digest();
  const sk   = Buffer.concat([seed, pub]);
  const enc  = encryptWallet(sk, pin);
  fs.writeFileSync(WALLET_F, enc, 'utf8');
  walletSK      = sk;
  walletPubkey  = b58enc(pub);
  walletLoaded  = true;
  log('info','WALLET CREATED', walletPubkey.slice(0,8)+'...');
  return walletPubkey;
}

async function walletImport(privkeyB58, pin) {
  const raw = b58dec(privkeyB58);
  if (raw.length < 32) throw new Error('Invalid private key length');
  const seed = raw.slice(0, 32);
  const pub  = raw.length === 64 ? raw.slice(32) : crypto.createHash('sha256').update(seed).digest();
  const sk   = Buffer.concat([seed, pub]);
  const enc  = encryptWallet(sk, pin);
  fs.writeFileSync(WALLET_F, enc, 'utf8');
  walletSK      = sk;
  walletPubkey  = b58enc(pub);
  walletLoaded  = true;
  log('info','WALLET IMPORTED', walletPubkey.slice(0,8)+'...');
  return walletPubkey;
}

async function walletUnlock(pin) {
  if (!fs.existsSync(WALLET_F)) throw new Error('No wallet file found. Create a wallet first.');
  const enc = fs.readFileSync(WALLET_F, 'utf8');
  const sk  = decryptWallet(enc, pin);
  walletSK      = sk;
  walletPubkey  = b58enc(sk.slice(32));
  walletLoaded  = true;
  log('info','WALLET UNLOCKED', walletPubkey.slice(0,8)+'...');
  await refreshBalance();
  return walletPubkey;
}

async function refreshBalance() {
  if (!walletPubkey) return;
  try {
    const r = await rpc('getBalance', [walletPubkey]);
    if (r?.value !== undefined) solBalance = r.value / LAMPORTS;
  } catch {}
}

// ── Runtime-configurable API key (survives restarts via env, overridable via settings) ──
let runtimeClaudeKey = C.CLAUDE_KEY; // can be updated via settings page without Railway redeploy

// ── SOL transfer transaction builder ─────────────────────
function buildSolTransferTx(fromPub, toPub, lamports, blockhash) {
  const fromBytes = b58dec(fromPub);
  const toBytes   = b58dec(toPub);
  const sysProg   = Buffer.alloc(32); // system program = all zeros

  // Message header: [numSigners, numReadonlySigned, numReadonlyUnsigned]
  const header = Buffer.from([1, 0, 1]);

  // Account list: from, to, system program
  const acctBuf = Buffer.alloc(1 + 3*32);
  acctBuf[0] = 3;
  fromBytes.copy(acctBuf, 1);
  toBytes.copy(acctBuf, 33);
  sysProg.copy(acctBuf, 65);

  // Blockhash
  const bhBuf = b58dec(blockhash);

  // SOL transfer instruction: SystemProgram.transfer (type=2)
  const data = Buffer.alloc(12);
  data.writeUInt32LE(2, 0);   // instruction type = 2 (transfer)
  data.writeBigUInt64LE(BigInt(lamports), 4);

  // Instruction: [progIdx=2][numAccts=2][from=0][to=1][dataLen][data]
  const instr = Buffer.from([2, 2, 0, 1, data.length, ...data]);
  const instrBuf = Buffer.concat([Buffer.from([1]), instr]); // 1 instruction

  // Assemble message
  const msg = Buffer.concat([header, acctBuf, bhBuf, instrBuf]);
  return msg;
}

async function sendSOL(toAddress, amountSOL, walletPin) {
  // Verify PIN by decrypting wallet
  const enc = fs.readFileSync(WALLET_F, 'utf8');
  const sk  = decryptWallet(enc, walletPin); // throws if wrong PIN

  const lamports = Math.floor(amountSOL * LAMPORTS);
  const bh = await rpc('getLatestBlockhash', [{commitment:'confirmed'}]);
  const blockhash = bh.value.blockhash;
  const fromPub = b58enc(sk.slice(32));

  const msg = buildSolTransferTx(fromPub, toAddress, lamports, blockhash);

  // Sign with Ed25519
  const seed   = sk.slice(0, 32);
  const keyObj = crypto.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});
  const sig    = crypto.sign(null, msg, keyObj);

  const signed = Buffer.concat([Buffer.from([1]), sig, msg]);
  const txSig  = await rpc('sendTransaction', [signed.toString('base64'), {encoding:'base64',skipPreflight:false,preflightCommitment:'confirmed'}]);
  return txSig;
}

function score(p) {
  const g1h=p.priceChange?.h1||0, g5m=p.priceChange?.m5||0, g6h=p.priceChange?.h6||0;
  const v5m=p.volume?.m5||0, v1h=p.volume?.h1||0, liq=p.liquidity?.usd||0, mc=p.fdv||p.marketCap||1;
  const b1h=p.txns?.h1?.buys||0, s1h=p.txns?.h1?.sells||1, b5m=p.txns?.m5?.buys||0, s5m=p.txns?.m5?.sells||1;
  const age=p.pairCreatedAt?(Date.now()-p.pairCreatedAt)/3600000:72;
  let s=0;
  if(mc>=10000&&mc<50000)s+=22;else if(mc>=50000&&mc<100000)s+=18;else if(mc>=100000&&mc<150000)s+=14;else if(mc>=150000&&mc<300000)s+=9;else if(mc>=300000&&mc<500000)s+=4;
  const vmr=v1h/(mc||1);if(vmr>=2)s+=20;else if(vmr>=1)s+=16;else if(vmr>=0.5)s+=11;else if(vmr>=0.2)s+=6;else if(vmr>=0.1)s+=3;
  s+=Math.min(10,v5m/((v1h/12)||1)*4);if(g5m>0&&g1h>0)s+=Math.min(6,g5m*.3);
  s+=Math.min(7,b1h/(b1h+s1h)*10);s+=Math.min(7,b5m/(b5m+s5m)*10);
  if(age>=0.25&&age<2)s+=12;else if(age>=2&&age<6)s+=10;else if(age>=6&&age<12)s+=8;else if(age>=12&&age<24)s+=5;else if(age>=24&&age<72)s+=2;else if(age<0.25)s+=6;
  if(liq>=8000&&liq<50000)s+=10;else if(liq>=50000&&liq<150000)s+=7;else if(liq>=5000&&liq<8000)s+=4;else if(liq>=150000)s+=3;
  const adj=g6h/Math.max(1,mc/50000);if(adj<50)s+=6;else if(adj<200)s+=3;else if(adj<500)s+=1;
  const bsr=b1h/(b1h+s1h);if(bsr<0.40)s-=20;else if(bsr<0.50)s-=10;else if(bsr<0.55)s-=4;
  if(liq<3000)s-=45;else if(liq<5000)s-=22;else if(liq<8000)s-=7;
  return Math.min(100,Math.max(0,Math.round(s)));
}

function kelly(base, conf) {
  const ep=brain.evolvedParams, kf=ep.kellyFraction||0.5;
  const wr=(wins+losses>4)?wins/(wins+losses):((brain.lifetimeWins+brain.lifetimeLosses>10)?brain.lifetimeWins/(brain.lifetimeWins+brain.lifetimeLosses):0.45);
  const b=2.5/0.35, raw=Math.max(0,(b*wr-(1-wr))/b);
  const wrM=0.2+wr*1.6, cM=Math.max(0.5,Math.min(1.6,(conf-40)/50+0.5)), kA=0.6+raw*kf*2;
  return Math.max(base*0.5,Math.min(base*2.5,base*wrM*cM*kA*Math.pow(0.75,Math.min(streak,4))));
}

function fmt(n) { return n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3).toFixed(0)+'K':n.toFixed(0); }

// ═══════════════════════════════════════════════════════════
//  MARKET DATA — 5 DexScreener sources in parallel
// ═══════════════════════════════════════════════════════════
const DEX_SOURCES = [
  ()=>get(`${DEX_API}/token-boosts/top/v1`).then(b=>{
    const mints=(Array.isArray(b)?b:[]).filter(t=>t.chainId==='solana').slice(0,30).map(t=>t.tokenAddress).join(',');
    return mints?get(`${DEX_API}/latest/dex/tokens/${mints}`).then(d=>(d.pairs||[]).filter(p=>p.chainId==='solana')):[];
  }),
  ()=>get(`${DEX_API}/latest/dex/search?q=solana`).then(d=>(d.pairs||[]).filter(p=>p.chainId==='solana')),
  ()=>get(`${DEX_API}/latest/dex/search?q=solana+meme`).then(d=>(d.pairs||[]).filter(p=>p.chainId==='solana')),
  ()=>get(`${DEX_API}/latest/dex/search?q=solana+moon`).then(d=>(d.pairs||[]).filter(p=>p.chainId==='solana')),
  ()=>get(`${DEX_API}/latest/dex/search?q=raydium+solana`).then(d=>(d.pairs||[]).filter(p=>p.chainId==='solana')),
];

async function fetchRunners() {
  const results = await Promise.allSettled(DEX_SOURCES.map(fn=>fn()));
  const seen=new Set(); let allPairs=[];
  for (const r of results) {
    if (r.status==='fulfilled') for (const p of r.value) {
      const id=p.pairAddress||p.baseToken?.address;
      if (id&&!seen.has(id)){seen.add(id);allPairs.push(p);}
    }
  }
  const ep=brain.totalTrades>=4?brain.evolvedParams:{};
  const bsr=ep.minBSR||1.1;
  const filtered=allPairs.filter(p=>{
    const liq=p.liquidity?.usd||0, mc=p.fdv||p.marketCap||0, g1h=p.priceChange?.h1||0;
    const b=p.txns?.h1?.buys||0, s=p.txns?.h1?.sells||1, vmr=(p.volume?.h1||0)/(mc||1);
    const age=p.pairCreatedAt?(Date.now()-p.pairCreatedAt)/3600000:999;
    if(liq<5000||liq>600000||mc<C.MIN_MC||mc>C.MAX_MC*3||g1h<10||b/s<bsr||age>240||vmr<0.05)return false;
    if(regime==='bear'&&(g1h<40||b/s<1.8||vmr<0.2))return false;
    return true;
  });
  return filtered.map(p=>{
    const mc=p.fdv||p.marketCap||0, age=p.pairCreatedAt?(Date.now()-p.pairCreatedAt)/3600000:72;
    const vmr=(p.volume?.h1||0)/(mc||1);
    let sc=score(p);
    if(mc<50000&&age<3&&vmr>=1)  sc=Math.min(100,sc+8);
    if(mc<100000&&age<6&&vmr>=0.5)sc=Math.min(100,sc+4);
    if(mc<30000&&age<2)           sc=Math.min(100,sc+5);
    return{p,sc};
  }).sort((a,b)=>b.sc-a.sc).slice(0,15).map(x=>x.p);
}

function updateRegime(runners) {
  if (!runners.length) return;
  const a=runners.reduce((s,r)=>s+(r.priceChange?.h1||0),0)/runners.length;
  const b=runners.filter(r=>(r.priceChange?.h1||0)>30).length;
  regime=a>40&&b>runners.length*0.6?'bull':a<10||b<runners.length*0.2?'bear':'neutral';
}

async function fetchPrice() {
  try {
    const d=await get(`https://price.jup.ag/v6/price?ids=${SOL_MINT}`);
    const p=d?.data?.[SOL_MINT]?.price; if(p) solPrice=p;
  } catch {}
}

// ═══════════════════════════════════════════════════════════
//  ANTIRUG SCAN
// ═══════════════════════════════════════════════════════════
async function antiRug(mint) {
  let risk=20;
  try {
    const mi=await rpc('getAccountInfo',[mint,{encoding:'jsonParsed'}]);
    if(mi?.value?.data?.parsed){const i=mi.value.data.parsed.info;if(i.mintAuthority)risk+=20;if(i.freezeAuthority)risk+=18;}
  } catch {}
  try {
    const gp=await get(`https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses=${mint}`);
    const i=gp?.result?.[mint]||gp?.result?.[mint?.toLowerCase()];
    if(i){if(i.is_honeypot==='1')risk+=55;if(parseFloat(i.sell_tax||0)>15)risk+=10;if(parseFloat(i.creator_percent||0)>30)risk+=8;}
  } catch {}
  return Math.min(100,risk);
}

// ═══════════════════════════════════════════════════════════
//  AI DECISIONS
// ═══════════════════════════════════════════════════════════
async function aiDecide(p, rsk) {
  const sym=p.baseToken?.symbol||'?', mc=p.fdv||p.marketCap||0;
  const sc=score(p), ep=brain.totalTrades>=4?brain.evolvedParams:{}, eff=ep.minScore||C.MIN_SCORE;
  if (!C.CLAUDE_KEY) {
    const buy=sc>=eff&&!(streak>=2&&sc<78);
    return{action:buy?'BUY':'SKIP',confidence:sc,positionMultiplier:sc>=80?1.4:1.0,reasoning:`[no-ai] score ${sc}/${eff}`};
  }
  const g1h=(p.priceChange?.h1||0).toFixed(0), vmr=((p.volume?.h1||0)/(mc||1)).toFixed(2);
  const b=p.txns?.h1?.buys||0, s=p.txns?.h1?.sells||1;
  const age=p.pairCreatedAt?((Date.now()-p.pairCreatedAt)/3600000).toFixed(1)+'h':'?';
  const prompt=`You are a low-cap gem hunter on Solana. Goal: $15K-$300K MC tokens that can reach $1M+.\n\n${learnedCtx()}\n\nTOKEN: ${sym} | MC: $${fmt(mc)} | Age: ${age} | Risk: ${rsk}/100 | Score: ${sc}/100\nVol/MC: ${vmr}x | 1h: +${g1h}% | BSR: ${(b/s).toFixed(2)}x | Regime: ${regime.toUpperCase()}\nPositions: ${positions.length}/${C.MAX_POS} | Streak: ${streak}${streak>=2?`\nCAUTION: require score ≥ 78`:''}\n\nReply ONLY JSON: {"action":"BUY","confidence":78,"positionMultiplier":1.2,"reasoning":"..."}\nOR {"action":"SKIP","confidence":35,"positionMultiplier":0,"reasoning":"..."}`;
  try {
    const d=await claudeCall(prompt,200);
    const txt=d?.content?.find(b=>b.type==='text')?.text||'';
    const parsed=JSON.parse(txt.replace(/```json|```/g,'').trim());
    return{...parsed,reasoning:parsed.reasoning||parsed.reason||'ok'};
  } catch {
    const buy=sc>=eff&&!(streak>=2&&sc<78);
    return{action:buy?'BUY':'SKIP',confidence:sc,positionMultiplier:1.0,reasoning:'[fallback]'};
  }
}

async function aiExit(pos, pct, trail, hrs, mult) {
  if (!C.CLAUDE_KEY) return{exit:trail>40&&mult<5,reason:'demo'};
  try {
    const d=await claudeCall(`Exit: ${pos.token} at ${mult.toFixed(1)}x (+${pct.toFixed(0)}%), trail -${trail.toFixed(0)}%, held ${hrs.toFixed(1)}h. Partials: 10x=${!!pos.p10} 50x=${!!pos.p50}. Goal 100x+. Only exit if momentum broken. {"exit":false,"reason":"..."} or {"exit":true,"reason":"..."}`,100);
    const txt=d?.content?.find(b=>b.type==='text')?.text||'{}';
    return JSON.parse(txt.replace(/```json|```/g,'').trim());
  } catch { return{exit:false,reason:'err'}; }
}

// ═══════════════════════════════════════════════════════════
//  JUPITER LIVE TRADING
// ═══════════════════════════════════════════════════════════
async function jupSwap(inMint, outMint, amtLamports, slipBps=1500) {
  if (!walletLoaded || !walletSK) throw new Error('Wallet not unlocked');

  // 1. Get quote
  const q = await get(`${JUP_Q}?inputMint=${inMint}&outputMint=${outMint}&amount=${amtLamports}&slippageBps=${slipBps}&onlyDirectRoutes=false`);
  if (q.error) throw new Error('Jupiter quote: '+q.error);

  // 2. Get swap transaction
  const sd = await post(JUP_SWAP, {
    quoteResponse:q, userPublicKey:walletPubkey,
    wrapAndUnwrapSol:true, prioritizationFeeLamports:100000,
    dynamicComputeUnitLimit:true, dynamicSlippage:{maxBps:3000},
  });
  if (sd.error) throw new Error('Jupiter swap: '+sd.error);

  // 3. Deserialize, sign, broadcast
  const txBytes=Buffer.from(sd.swapTransaction,'base64');
  const numSigs=txBytes[0];
  const msgOffset=1+(numSigs*64);
  const msgBytes=txBytes.slice(msgOffset);

  // Sign with Ed25519 (Node.js crypto supports this natively in v18+)
  const seed=walletSK.slice(0,32);
  const keyObj=crypto.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});
  const sig=crypto.sign(null, msgBytes, keyObj);

  const signed=Buffer.concat([Buffer.from([1]),sig,msgBytes]);
  const txSig=await rpc('sendTransaction',[signed.toString('base64'),{encoding:'base64',skipPreflight:false,preflightCommitment:'confirmed',maxRetries:3}]);

  // 4. Wait for confirmation
  for (let i=0;i<30;i++) {
    await sleep(1000);
    try {
      const status=await rpc('getSignatureStatuses',[[txSig]]);
      const s=status?.value?.[0];
      if (s?.err) throw new Error('Tx failed: '+JSON.stringify(s.err));
      if (s?.confirmationStatus==='confirmed'||s?.confirmationStatus==='finalized') break;
    } catch(e) { if (e.message.includes('Tx failed')) throw e; }
  }
  return{txSig, outAmount:BigInt(q.outAmount||0)};
}

async function getTokenBalance(mint) {
  try {
    const r=await rpc('getTokenAccountsByOwner',[walletPubkey,{mint},{encoding:'jsonParsed'}]);
    const accts=r?.value||[];
    if(!accts.length)return 0n;
    const amt=accts[0]?.account?.data?.parsed?.info?.tokenAmount?.amount||'0';
    return BigInt(amt);
  } catch { return 0n; }
}

// ═══════════════════════════════════════════════════════════
//  TRADING (paper + live)
// ═══════════════════════════════════════════════════════════
async function doBuy(p, dec, rsk) {
  const sym=p.baseToken?.symbol||'?', mint=p.baseToken?.address||'';
  const price=parseFloat(p.priceUsd||0)||(solPrice*1e-6);
  const posSOL=kelly(C.POS_SOL,dec.confidence)*(dec.positionMultiplier||1);
  const mc=p.fdv||p.marketCap||0;
  const meta={bsr:+(p.txns?.h1?(p.txns.h1.buys/(p.txns.h1.sells||1)):1).toFixed(2),g1h:p.priceChange?.h1||0,age:p.pairCreatedAt?(Date.now()-p.pairCreatedAt)/3600000:48,mc,liq:p.liquidity?.usd||0,score:score(p),regime};

  if (C.MODE==='paper') {
    const cost=Math.min(posSOL*solPrice,paperBal*0.85);
    if(cost<0.5){log('skip',`LOW BAL ${sym}`,'');return;}
    paperBal-=cost;
    positions.push({token:sym,mint,entry:price,current:price,size:cost,sol:posSOL,tokenBal:0n,isLive:false,aiScore:dec.confidence,risk:rsk,openedAt:Date.now(),peak:price,p10:false,p50:false,p100:false,meta});
    pyrs[mint]=0;
    log('buy',`PAPER BUY ${sym}`,`$${cost.toFixed(2)} · score ${dec.confidence} · ${(dec.reasoning||'').slice(0,60)}`);
    return;
  }

  // ── LIVE MODE ──────────────────────────────────────────
  if (!walletLoaded) { log('warn',`LIVE BUY SKIP ${sym}`,'Wallet not unlocked'); return; }
  const availSOL = solBalance - 0.01; // keep 0.01 for fees
  const actualSOL = Math.min(posSOL, availSOL);
  if (actualSOL < 0.005) { log('skip',`LOW SOL ${sym}`,`need ${posSOL.toFixed(4)} have ${solBalance.toFixed(4)}`); return; }

  log('buy',`LIVE BUY ${sym}`,`Swapping ${actualSOL.toFixed(4)} SOL via Jupiter...`);
  try {
    const lamports = Math.floor(actualSOL * LAMPORTS);
    const {txSig, outAmount} = await jupSwap(SOL_MINT, mint, lamports);
    await sleep(2000);
    const tokenBal = await getTokenBalance(mint) || outAmount;
    const cost = actualSOL * solPrice;
    positions.push({token:sym,mint,entry:price,current:price,size:cost,sol:actualSOL,tokenBal,isLive:true,liveSig:txSig,aiScore:dec.confidence,risk:rsk,openedAt:Date.now(),peak:price,p10:false,p50:false,p100:false,meta});
    pyrs[mint]=0;
    await refreshBalance();
    log('buy',`⚡ LIVE BOUGHT ${sym}`,`${actualSOL.toFixed(4)} SOL · tx:${txSig.slice(0,12)}...`);
  } catch(e) {
    log('warn',`LIVE BUY FAILED ${sym}`,e.message.slice(0,80));
  }
}

async function doPartial(i, p, pct, frac, label) {
  if (p.isLive) {
    const sellTokens = BigInt(Math.floor(Number(p.tokenBal) * frac));
    if (sellTokens <= 0n) return;
    try {
      const {txSig} = await jupSwap(p.mint, SOL_MINT, sellTokens, 2500);
      p.tokenBal -= sellTokens;
      p.size *= (1 - frac);
      await refreshBalance();
      log('sell',`⚡ ${label}: ${p.token}`,`tx:${txSig.slice(0,12)}...`);
    } catch(e) { log('warn',`PARTIAL FAIL ${p.token}`,e.message.slice(0,60)); }
  } else {
    const ps=p.size*frac, pp=ps*pct/100;
    paperBal+=ps+pp; p.size-=ps;
    log('sell',`${label}: ${p.token}`,`+$${pp.toFixed(2)} rem $${p.size.toFixed(2)}`);
  }
}

async function doExit(i, p, pct, reason) {
  if (p.isLive) {
    if (p.tokenBal > 0n) {
      try {
        const {txSig} = await jupSwap(p.mint, SOL_MINT, p.tokenBal, 2500);
        log('sell',`⚡ LIVE EXIT ${p.token}`,`${reason} · tx:${txSig.slice(0,12)}...`);
        await refreshBalance();
      } catch(e) {
        log('warn',`LIVE EXIT FAIL ${p.token}`,e.message.slice(0,60)+' — retry or manual exit');
        return; // Don't remove position — let user retry
      }
    }
  }
  const pnl=p.size*pct/100;
  if (!p.isLive) paperBal+=p.size+pnl;
  const t={token:p.token,entry:p.entry,exit:p.current,pnl,pct,size:p.size,isLive:p.isLive||false,openedAt:p.openedAt,closedAt:Date.now()};
  positions.splice(i,1); trades.push(t); saveJ(TRADES_F,trades);
  if(pnl>0){wins++;streak=0;}else{losses++;streak++;}
  learnFromTrade(t,p.meta);
  log('sell',`EXIT ${p.token}`,`${reason} · P&L ${pnl>=0?'+':''}$${pnl.toFixed(2)} (${pct.toFixed(0)}%)`);
}

async function updatePrices() {
  for (const p of positions) {
    try {
      const d=await get(`${DEX_API}/latest/dex/tokens/${p.mint}`);
      const pp=(d.pairs||[]).find(x=>x.chainId==='solana');
      if(pp){const n=parseFloat(pp.priceUsd||0);if(n>0){p.current=n;if(n>p.peak)p.peak=n;}}
      if(p.isLive&&p.mint){const b=await getTokenBalance(p.mint);if(b>0n)p.tokenBal=b;}
    } catch {}
    await sleep(200);
  }
}

async function checkExits() {
  const sl=regime==='bear'?Math.round(C.STOP_PCT*.7):C.STOP_PCT;
  const ts=regime==='bear'?Math.round(C.TRAIL_PCT*.7):C.TRAIL_PCT;
  for (let i=positions.length-1;i>=0;i--) {
    const p=positions[i];
    const pct=p.entry?(p.current-p.entry)/p.entry*100:0;
    const trail=p.peak?(p.peak-p.current)/p.peak*100:0;
    const hrs=(Date.now()-p.openedAt)/3600000, mult=p.current/p.entry;
    if(!p.p10&&mult>=10){p.p10=true;await doPartial(i,p,pct,.20,'🚀 10x');continue;}
    if(!p.p50&&mult>=50){p.p50=true;await doPartial(i,p,pct,.20,'💎 50x');continue;}
    if(!p.p100&&mult>=100){p.p100=true;await doPartial(i,p,pct,.20,'🌕 100x');continue;}
    const n=pyrs[p.mint]||0;
    if(n<3&&regime!=='bear'){
      const mst=[3,10,30][n];
      if(mult>=mst){
        pyrs[p.mint]=(n+1);
        if(p.isLive){
          const addSOL=Math.min(C.POS_SOL*[.5,.35,.2][n],solBalance*.25);
          if(addSOL>=0.005){
            try{const{txSig,outAmount}=await jupSwap(SOL_MINT,p.mint,Math.floor(addSOL*LAMPORTS));const nb=await getTokenBalance(p.mint);p.tokenBal=nb||p.tokenBal+outAmount;const addUSD=addSOL*solPrice;const tot=p.size+addUSD;p.entry=(p.size*p.entry+addUSD*p.current)/tot;p.size=tot;await refreshBalance();log('buy',`⚡ PYRAMID #${n+1} ${p.token}`,`+${addSOL.toFixed(4)} SOL · tx:${txSig.slice(0,8)}...`);}catch(e){log('warn',`PYRAMID FAIL ${p.token}`,e.message.slice(0,60));}
          }
        } else {
          const add=Math.min(p.size*[.5,.35,.2][n],paperBal*.25);
          if(add>=.5){paperBal-=add;const tot=p.size+add;p.entry=(p.size*p.entry+add*p.current)/tot;p.size=tot;log('buy',`PYRAMID #${n+1} ${p.token}`,`+$${add.toFixed(2)} at ${mult.toFixed(1)}x`);}
        }
      }
    }
    let reason=null;
    if(pct<=-sl)reason=`Stop -${sl}%`;
    else if(trail>=ts&&pct>20)reason=`Trail -${ts}%`;
    else if(hrs>=C.MAX_HOLD)reason=`Time ${C.MAX_HOLD}h`;
    if(!reason&&pct>30){const ae=await aiExit(p,pct,trail,hrs,mult);if(ae.exit)reason=ae.reason;}
    if(reason)await doExit(i,p,pct,reason);
  }
}

function sleep(ms){return new Promise(r=>setTimeout(r,ms));}

// ═══════════════════════════════════════════════════════════
//  MAIN CYCLE
// ═══════════════════════════════════════════════════════════
async function runCycle() {
  if (!running) return;
  cycle++;
  log('info',`CYCLE #${cycle}`,`${C.MODE} · ${positions.length}pos · bal:${C.MODE==='paper'?'$'+paperBal.toFixed(2):solBalance.toFixed(4)+' SOL'}`);
  try {
    await fetchPrice();
    const runners=await fetchRunners();
    lastScanStats={total:runners.length,sources:5,filtered:runners.length,runners};
    updateRegime(runners);
    log('scan','SCAN',`${runners.length} gems found · regime: ${regime}`);
    await checkExits();
    if(positions.length<C.MAX_POS&&runners.length){
      const todo=runners.filter(p=>{const m=p.baseToken?.address;return m&&!positions.some(x=>x.mint===m)&&!analyzing.has(m);}).slice(0,3);
      for(const p of todo){
        if(!running)break;
        const mint=p.baseToken?.address,sym=p.baseToken?.symbol||'?';
        analyzing.add(mint);
        try{
          let rsk=25;
          if(C.ANTIRUG)rsk=await antiRug(mint);
          if(rsk>C.MAX_RISK){log('skip',`ANTIRUG ${sym}`,`risk ${rsk}/100`);continue;}
          const dec=await aiDecide(p,rsk);
          if(dec.action==='BUY')await doBuy(p,dec,rsk);
          else log('skip',`SKIP ${sym}`,dec.reasoning.slice(0,70));
        }catch(e){log('warn',`ERR ${sym}`,e.message.slice(0,70));}
        analyzing.delete(mint);
      }
    }
    await updatePrices();
    if(C.MODE==='live')await refreshBalance();
  } catch(e){log('warn','CYCLE ERR',e.message.slice(0,70));}
  if(running)nextTimer=setTimeout(runCycle,C.INTERVAL*1000);
}

// ═══════════════════════════════════════════════════════════
//  DASHBOARD HTML
// ═══════════════════════════════════════════════════════════
function walletHasFile() { return fs.existsSync(WALLET_F); }

function loginPage(error='') {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>🌕 Gem Hunter — Login</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#070a10;color:#d4e5ff;font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
.box{background:#0d1117;border:1px solid #1a2332;border-radius:14px;padding:28px;width:100%;max-width:360px}
h1{font-size:22px;font-weight:800;margin-bottom:6px;background:linear-gradient(90deg,#8b5cf6,#f5a623,#00e87a);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
p{font-size:12px;color:#4a6080;margin-bottom:20px}
input{width:100%;background:#070a10;border:1px solid #1a2332;border-radius:8px;padding:11px 14px;color:#d4e5ff;font-size:14px;margin-bottom:10px;font-family:monospace}
input:focus{outline:none;border-color:#8b5cf6}
button{width:100%;padding:12px;border-radius:8px;border:none;font-size:14px;font-weight:700;cursor:pointer;margin-bottom:8px;font-family:inherit}
.btn-g{background:#00e87a;color:#000}.btn-p{background:#8b5cf6;color:#fff}.btn-b{background:#1a2332;color:#4a6080}
.err{background:rgba(255,51,85,.1);border:1px solid rgba(255,51,85,.3);border-radius:7px;padding:8px 12px;font-size:12px;color:#ff3355;margin-bottom:12px}
.tab{display:flex;gap:4px;margin-bottom:16px}
.tab-btn{flex:1;padding:7px;border-radius:6px;border:none;font-size:12px;font-weight:600;cursor:pointer;background:#1a2332;color:#4a6080;font-family:inherit}
.tab-btn.active{background:#8b5cf6;color:#fff}
section{display:none}.section.active{display:block}
</style></head><body>
<div class="box">
  <h1>🌕 GEM HUNTER</h1>
  <p>Secure AI trading bot</p>
  ${error?`<div class="err">❌ ${error}</div>`:''}
  <div class="tab">
    <button class="tab-btn active" onclick="show('unlock')">Unlock</button>
    <button class="tab-btn" onclick="show('create')">Create</button>
    <button class="tab-btn" onclick="show('import')">Import</button>
  </div>

  <div id="unlock" class="section active">
    <form method="POST" action="/auth/unlock">
      ${C.DASH_PIN?`<input name="dashpin" type="password" placeholder="Dashboard PIN" autocomplete="off"><br>`:''}
      <input name="pin" type="password" placeholder="Wallet PIN" autocomplete="new-password">
      <button class="btn-g" type="submit">🔓 Unlock Wallet</button>
    </form>
    ${!walletHasFile()?'<p style="color:#ffb020;margin-top:8px;font-size:11px">⚠️ No wallet found. Create or import one.</p>':''}
  </div>

  <div id="create" class="section">
    <form method="POST" action="/auth/create">
      ${C.DASH_PIN?`<input name="dashpin" type="password" placeholder="Dashboard PIN" autocomplete="off"><br>`:''}
      <input name="pin" type="password" placeholder="Choose wallet PIN (min 6 chars)" autocomplete="new-password">
      <input name="pin2" type="password" placeholder="Confirm PIN" autocomplete="new-password">
      <button class="btn-p" type="submit">✨ Create New Wallet</button>
    </form>
  </div>

  <div id="import" class="section">
    <form method="POST" action="/auth/import">
      ${C.DASH_PIN?`<input name="dashpin" type="password" placeholder="Dashboard PIN" autocomplete="off"><br>`:''}
      <input name="privkey" type="password" placeholder="Base58 private key" autocomplete="off">
      <input name="pin" type="password" placeholder="New PIN for this wallet" autocomplete="new-password">
      <button class="btn-b" type="submit">📥 Import Wallet</button>
    </form>
  </div>
</div>
<script>
function show(id){
  document.querySelectorAll('.section').forEach(s=>s.style.display='none');
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById(id).style.display='block';
  event.target.classList.add('active');
}
</script>
</body></html>`;
}

function dashPage() {
  const total=C.MODE==='paper'
    ? paperBal+positions.filter(p=>!p.isLive).reduce((s,p)=>s+p.size*((p.current||p.entry)/p.entry),0)
    : solBalance * solPrice;
  const startV=C.MODE==='paper'?C.START_BAL:0;
  const pnl=total-startV;
  const ws=trades.filter(t=>t.pnl>0), ls=trades.filter(t=>t.pnl<=0);
  const avgW=ws.length?ws.reduce((a,t)=>a+t.pnl,0)/ws.length:0;
  const avgL=ls.length?ls.reduce((a,t)=>a+Math.abs(t.pnl),0)/ls.length:0.001;
  const up=startedAt?Math.floor((Date.now()-startedAt)/1000):0;
  const upStr=`${Math.floor(up/3600)}:${String(Math.floor((up%3600)/60)).padStart(2,'0')}:${String(up%60).padStart(2,'0')}`;
  const best=trades.length?trades.reduce((a,b)=>b.pnl>a.pnl?b:a,{pnl:-999,token:'—',pct:0}):null;

  const posR=positions.map((p,i)=>{
    const pct=p.entry?(p.current-p.entry)/p.entry*100:0, m=p.current/p.entry;
    const mc=p.meta?.mc||0;
    return`<tr>
      <td><b>${p.token}</b>${p.isLive?'<span style="font-size:9px;background:rgba(255,51,85,.15);color:#ff3355;border:1px solid rgba(255,51,85,.3);border-radius:3px;padding:1px 4px;margin-left:4px">⚡LIVE</span>':''}<br><span style="font-size:10px;color:${mc<50000?'#00e87a':mc<150000?'#ffb020':'#4a6080'}">$${fmt(mc)}</span></td>
      <td>$${p.size.toFixed(1)}</td>
      <td style="color:${pct>=0?'#00e87a':'#ff3355'};font-weight:700">${pct>=0?'+':''}${pct.toFixed(0)}%</td>
      <td style="color:${m>=100?'#f5a623':m>=10?'#8b5cf6':m>=3?'#00e87a':'#4a6080'};font-weight:700">${m.toFixed(m>=10?1:2)}x</td>
      <td><a href="/exit/${i}" style="color:#ff3355;text-decoration:none;font-size:12px">${p.isLive?'⚡':'✕'}</a></td>
    </tr>`;
  }).join('');

  const tR=trades.slice(-10).reverse().map(t=>
    `<tr><td>${t.token}${t.isLive?'<span style="font-size:9px;color:#ff3355;margin-left:3px">⚡</span>':''}</td><td style="color:${t.pnl>=0?'#00e87a':'#ff3355'}">${t.pnl>=0?'+':''}$${t.pnl.toFixed(2)}</td><td>${t.pct.toFixed(0)}%</td></tr>`
  ).join('');

  const gemRows=lastScanStats.runners.slice(0,8).map(r=>{
    const mc=r.fdv||r.marketCap||0, g1h=r.priceChange?.h1||0;
    const vmr=((r.volume?.h1||0)/(mc||1)).toFixed(1), sc2=score(r);
    return`<div style="display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid #1a2332;font-size:11px">
      <b>${r.baseToken?.symbol||'?'}</b>
      <span style="color:${mc<50000?'#00e87a':mc<150000?'#ffb020':'#4a6080'};font-family:monospace">$${fmt(mc)}</span>
      <span style="color:#00e87a;font-family:monospace">+${g1h.toFixed(0)}%</span>
      <span style="color:#8b5cf6;font-family:monospace">${vmr}x</span>
      <span style="color:#ffb020;font-weight:700">${sc2}/100</span>
    </div>`;
  }).join('');

  const lR=logs.slice(0,40).map(l=>{
    const c={buy:'#00e87a',sell:'#ff3355',skip:'#4a6080',info:'#3b9eff',warn:'#ffb020',scan:'#8b5cf6'}[l.type]||'#d4e5ff';
    return`<div style="padding:3px 0;border-bottom:1px solid #111;font-size:11px"><span style="color:#4a6080">${l.ts.slice(11,19)}</span> <span style="color:${c};font-weight:600">${l.label}</span> <span style="color:#4a6080">${(l.detail||'').slice(0,80)}</span></div>`;
  }).join('');

  const ins=brain.insights.length?`"${brain.insights[0].text.slice(0,200)}"`:'"Run the bot for a few trades to generate AI insights."';
  const modeColor=C.MODE==='live'?'#ff3355':'#3b9eff';
  const walletDisplay=walletPubkey?walletPubkey.slice(0,6)+'...'+walletPubkey.slice(-4):'not loaded';
  const balDisplay=C.MODE==='live'?`${solBalance.toFixed(4)} SOL ($${(solBalance*solPrice).toFixed(2)})`:`$${paperBal.toFixed(2)} paper`;

  return`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>🌕 Gem Hunter</title><meta http-equiv="refresh" content="15">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#070a10;color:#d4e5ff;font-family:system-ui,sans-serif;font-size:13px;padding:12px}
h2{font-size:11px;font-weight:700;color:#4a6080;text-transform:uppercase;letter-spacing:.08em;margin:14px 0 7px}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px}
.card{background:#0d1117;border:1px solid #1a2332;border-radius:9px;padding:9px 11px}
.lbl{font-size:10px;color:#4a6080;text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px}
.val{font-size:17px;font-weight:700;font-family:monospace}
.g{color:#00e87a}.r{color:#ff3355}.p{color:#8b5cf6}.a{color:#ffb020}.b{color:#3b9eff}
.top{display:flex;align-items:center;gap:8px;background:#0d1117;border:1px solid #1a2332;border-radius:8px;padding:9px 12px;margin-bottom:10px;flex-wrap:wrap}
.dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.on{background:#00e87a;box-shadow:0 0 6px #00e87a;animation:pulse 1.5s infinite}
.off{background:#4a6080}
@keyframes pulse{50%{opacity:.3}}
.btn-row{display:flex;gap:7px;margin-bottom:10px;flex-wrap:wrap}
a.btn{display:inline-block;padding:8px 16px;border-radius:7px;font-weight:700;font-size:13px;text-decoration:none}
.bg{background:#00e87a;color:#000}.br{background:#ff3355;color:#fff}.bx{background:#1a2332;color:#d4e5ff}.blo{background:#ff9500;color:#000}
table{width:100%;border-collapse:collapse;font-size:11px}
th{text-align:left;padding:5px 6px;color:#4a6080;font-weight:600;border-bottom:1px solid #1a2332;font-size:10px;text-transform:uppercase}
td{padding:6px;border-bottom:1px solid #0d1117}
.tw{background:#0d1117;border:1px solid #1a2332;border-radius:8px;overflow:hidden;margin-bottom:10px}
.log{background:#0d1117;border:1px solid #1a2332;border-radius:8px;padding:10px;height:190px;overflow-y:auto;font-family:monospace}
.brain{display:flex;gap:12px;flex-wrap:wrap;background:#0d1117;border:1px solid #1a2332;border-radius:8px;padding:9px 12px;margin-bottom:10px}
.bi{display:flex;flex-direction:column;gap:2px}
.bl{font-size:9px;text-transform:uppercase;color:#4a6080}
.bv{font-family:monospace;font-size:13px;font-weight:700}
.ins{background:#0d1117;border:1px solid rgba(139,92,246,.2);border-radius:8px;padding:9px 12px;font-size:12px;line-height:1.6;margin-bottom:10px;font-style:italic;color:#c8c0ff}
.wallet-bar{display:flex;align-items:center;gap:8px;background:#0d1117;border:1px solid rgba(0,232,122,.2);border-radius:8px;padding:8px 12px;margin-bottom:10px;flex-wrap:wrap}
.dex{background:#0d1117;border:1px solid #1a2332;border-radius:8px;padding:9px 12px;margin-bottom:10px}
</style></head><body>

<div style="font-size:19px;font-weight:800;margin-bottom:10px;background:linear-gradient(90deg,#8b5cf6,#f5a623,#00e87a);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text">🌕 GEM HUNTER</div>

${navBar('/')}

<!-- Wallet bar -->
<div class="wallet-bar">
  <span style="font-size:11px;color:#4a6080">🔐 WALLET</span>
  <span style="font-family:monospace;font-size:12px;color:#00e87a">${walletDisplay}</span>
  <span style="font-size:11px;color:#4a6080">|</span>
  <span style="font-family:monospace;font-size:12px;font-weight:700;color:${C.MODE==='live'?'#00e87a':'#3b9eff'}">${balDisplay}</span>
  <span style="margin-left:auto;font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;background:${C.MODE==='live'?'rgba(255,51,85,.15)':'rgba(59,158,255,.15)'};color:${modeColor};border:1px solid ${modeColor}">${C.MODE.toUpperCase()}</span>
</div>

<div class="top">
  <span class="dot ${running?'on':'off'}"></span>
  <b>${running?'RUNNING':'STOPPED'}</b>
  <span style="color:#4a6080">· cycle #${cycle} · ${upStr}</span>
  <span style="margin-left:auto;color:#4a6080">SOL $${solPrice.toFixed(2)} · <span style="color:${regime==='bull'?'#00e87a':regime==='bear'?'#ff3355':'#ffb020'}">${regime.toUpperCase()}</span></span>
</div>

<div class="btn-row">
  <a href="/start" class="btn bg">▶ START</a>
  <a href="/stop"  class="btn br">■ STOP</a>
  <a href="/"      class="btn bx">↻ Refresh</a>
  <a href="/lock"  class="btn bx">🔒 Lock</a>
</div>

<div class="g2">
  <div class="card"><div class="lbl">Portfolio</div><div class="val ${pnl>=0?'g':'r'}">$${total.toFixed(2)}</div><div style="font-size:11px;color:#4a6080">${pnl>=0?'+':''}$${pnl.toFixed(2)} (${(pnl/(startV||1)*100).toFixed(1)}%)</div></div>
  <div class="card"><div class="lbl">Win Rate</div><div class="val">${trades.length?(ws.length/trades.length*100).toFixed(1)+'%':'—'}</div><div style="font-size:11px;color:#4a6080">${wins}W / ${losses}L · ${trades.length} trades</div></div>
  <div class="card"><div class="lbl">Profit Factor</div><div class="val ${avgW/avgL>=1.5?'g':avgW/avgL>=1?'a':'r'}">${(avgW/avgL).toFixed(2)}</div><div style="font-size:11px;color:#4a6080">$${avgW.toFixed(2)} win / $${avgL.toFixed(2)} loss</div></div>
  <div class="card"><div class="lbl">Best Trade</div><div class="val g">${best&&best.pnl>-999?'+$'+best.pnl.toFixed(2):'—'}</div><div style="font-size:11px;color:#4a6080">${best&&best.pnl>-999?best.token+' +'+best.pct.toFixed(0)+'%':'—'}</div></div>
</div>

<div class="dex">
  <div style="display:flex;justify-content:space-between;margin-bottom:7px"><span style="font-size:11px;font-weight:700;color:#8b5cf6">📡 DEXSCREENER — 5 SOURCES</span><span style="font-size:10px;color:#4a6080">${lastScanStats.filtered} gems found</span></div>
  <div style="display:flex;gap:5px;flex-wrap:wrap;margin-bottom:8px">
    ${['Token Boosts','New Pairs','Meme','Moon','Raydium'].map(s=>`<span style="font-size:10px;padding:2px 7px;border-radius:10px;background:rgba(0,232,122,.1);border:1px solid rgba(0,232,122,.25);color:#00e87a">${s}</span>`).join('')}
  </div>
  ${gemRows||'<div style="color:#4a6080;font-size:11px;text-align:center;padding:6px">Start the bot to see live gems</div>'}
</div>

<div class="brain">
  <div class="bi"><div class="bl">Epoch</div><div class="bv p">${brain.epoch}</div></div>
  <div class="bi"><div class="bl">Brain</div><div class="bv">${brain.totalTrades} trades</div></div>
  <div class="bi"><div class="bl">Min BSR</div><div class="bv b">${brain.evolvedParams.minBSR.toFixed(2)}x</div></div>
  <div class="bi"><div class="bl">Min Score</div><div class="bv b">${brain.evolvedParams.minScore}</div></div>
  <div class="bi"><div class="bl">Kelly</div><div class="bv b">${(brain.evolvedParams.kellyFraction*100).toFixed(0)}%</div></div>
</div>

<div class="ins">🧠 ${ins}</div>

<h2>Open Positions (${positions.length}/${C.MAX_POS})</h2>
<div class="tw">${positions.length?`<table><thead><tr><th>Token</th><th>Size</th><th>P&L</th><th>Mult</th><th></th></tr></thead><tbody>${posR}</tbody></table>`:'<div style="padding:12px;color:#4a6080;text-align:center">No open positions</div>'}</div>

<h2>Recent Trades</h2>
<div class="tw">${trades.length?`<table><thead><tr><th>Token</th><th>P&L</th><th>Return</th></tr></thead><tbody>${tR}</tbody></table>`:'<div style="padding:12px;color:#4a6080;text-align:center">No trades yet</div>'}</div>

<h2>Live Log</h2>
<div class="log">${lR}</div>
<div style="color:#4a6080;font-size:10px;margin-top:10px;text-align:center">Auto-refreshes every 15s · <a href="/api/state" style="color:#3b9eff">JSON API</a></div>
</body></html>`;
}

// ── Shared nav bar ────────────────────────────────────────
function navBar(active='home') {
  const tabs=[['/',      '🏠','Home'],
              ['/deposit','📥','Deposit'],
              ['/withdraw','📤','Withdraw'],
              ['/settings','⚙️','Settings']];
  return`<div style="display:flex;gap:2px;background:#0d1117;border:1px solid #1a2332;border-radius:10px;padding:4px;margin-bottom:12px">
    ${tabs.map(([href,icon,label])=>{
      const on=active===href;
      return`<a href="${href}" style="flex:1;text-align:center;padding:8px 4px;border-radius:7px;text-decoration:none;font-size:12px;font-weight:${on?'700':'500'};background:${on?'#1a2332':'transparent'};color:${on?'#d4e5ff':'#4a6080'}">${icon}<br><span style="font-size:10px">${label}</span></a>`;
    }).join('')}
  </div>`;
}

// ── Deposit page ──────────────────────────────────────────
function depositPage(msg='') {
  const qrUrl = walletPubkey
    ? `https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${walletPubkey}`
    : '';
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>📥 Deposit</title><meta http-equiv="refresh" content="30"><style>
*{box-sizing:border-box;margin:0;padding:0}body{background:#070a10;color:#d4e5ff;font-family:system-ui,sans-serif;font-size:13px;padding:12px;max-width:480px;margin:0 auto}
input{width:100%;background:#0d1117;border:1px solid #1a2332;border-radius:8px;padding:10px 12px;color:#d4e5ff;font-size:12px;font-family:monospace;margin-bottom:10px;word-break:break-all}
.btn{display:block;width:100%;padding:11px;border-radius:8px;border:none;font-size:13px;font-weight:700;cursor:pointer;text-align:center;text-decoration:none;font-family:inherit;margin-bottom:8px}
.bg{background:#00e87a;color:#000}.bx{background:#1a2332;color:#4a6080}
.card{background:#0d1117;border:1px solid #1a2332;border-radius:10px;padding:14px;margin-bottom:10px}
.lbl{font-size:10px;color:#4a6080;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px}
.ok{background:rgba(0,232,122,.1);border:1px solid rgba(0,232,122,.3);border-radius:7px;padding:9px 12px;font-size:12px;color:#00e87a;margin-bottom:10px}
h1{font-size:16px;font-weight:700;margin-bottom:10px}
</style></head><body>
<h1>🌕 Gem Hunter</h1>
${navBar('/deposit')}
${msg?`<div class="ok">${msg}</div>`:''}

<div class="card">
  <div class="lbl">Your Solana Address</div>
  <input type="text" value="${walletPubkey||'Wallet not loaded'}" readonly onclick="this.select()">
  <a href="/deposit/copy" class="btn bg">📋 Copy Address</a>
  <a href="/deposit/refresh" class="btn bx">↻ Refresh Balance</a>
</div>

${walletPubkey?`<div class="card" style="text-align:center">
  <div class="lbl" style="margin-bottom:10px">Scan to Deposit</div>
  <img src="${qrUrl}" alt="QR Code" style="border-radius:8px;max-width:180px">
  <div style="font-size:11px;color:#4a6080;margin-top:8px">Scan with Phantom or any Solana wallet</div>
</div>`:''}

<div class="card">
  <div class="lbl">Current Balance</div>
  <div style="font-size:22px;font-weight:800;font-family:monospace;color:#00e87a">${solBalance.toFixed(4)} ◎</div>
  <div style="font-size:12px;color:#4a6080;margin-top:3px">≈ $${(solBalance*solPrice).toFixed(2)} · SOL $${solPrice.toFixed(2)}</div>
</div>

<div style="background:rgba(255,176,32,.07);border:1px solid rgba(255,176,32,.2);border-radius:8px;padding:10px 12px;font-size:11px;color:#ffb020;line-height:1.6">
  ⚠️ Only send SOL to this address. Sending other tokens may result in loss.
</div>
<br>
<a href="/" class="btn bx">← Back to Dashboard</a>
</body></html>`;
}

// ── Withdraw page ─────────────────────────────────────────
function withdrawPage(result='', error='') {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>📤 Withdraw</title><style>
*{box-sizing:border-box;margin:0;padding:0}body{background:#070a10;color:#d4e5ff;font-family:system-ui,sans-serif;font-size:13px;padding:12px;max-width:480px;margin:0 auto}
input,select{width:100%;background:#0d1117;border:1px solid #1a2332;border-radius:8px;padding:10px 12px;color:#d4e5ff;font-size:13px;font-family:monospace;margin-bottom:10px}
input:focus{outline:none;border-color:#8b5cf6}
.btn{display:block;width:100%;padding:11px;border-radius:8px;border:none;font-size:13px;font-weight:700;cursor:pointer;text-align:center;text-decoration:none;font-family:inherit;margin-bottom:8px}
.br{background:#ff3355;color:#fff}.bx{background:#1a2332;color:#4a6080}
.card{background:#0d1117;border:1px solid #1a2332;border-radius:10px;padding:14px;margin-bottom:10px}
.lbl{font-size:11px;color:#4a6080;margin-bottom:5px}
.ok{background:rgba(0,232,122,.1);border:1px solid rgba(0,232,122,.3);border-radius:7px;padding:9px 12px;font-size:12px;color:#00e87a;margin-bottom:10px;word-break:break-all}
.err{background:rgba(255,51,85,.1);border:1px solid rgba(255,51,85,.3);border-radius:7px;padding:9px 12px;font-size:12px;color:#ff3355;margin-bottom:10px}
h1{font-size:16px;font-weight:700;margin-bottom:10px}
a{color:#3b9eff}
</style></head><body>
<h1>🌕 Gem Hunter</h1>
${navBar('/withdraw')}
${result?`<div class="ok">✅ Sent! <a href="https://solscan.io/tx/${result}" target="_blank" style="font-family:monospace;font-size:11px">${result.slice(0,20)}... → Solscan ↗</a></div>`:''}
${error?`<div class="err">❌ ${error}</div>`:''}

<div class="card">
  <div class="lbl">Available Balance</div>
  <div style="font-size:20px;font-weight:800;font-family:monospace;color:#00e87a">${solBalance.toFixed(4)} ◎</div>
  <div style="font-size:11px;color:#4a6080;margin-top:2px">≈ $${(solBalance*solPrice).toFixed(2)} · Keep ~0.002 SOL for fees</div>
</div>

<form method="POST" action="/withdraw/send">
  <div class="lbl">Recipient Solana Address</div>
  <input name="to" type="text" placeholder="Solana address (base58)" autocomplete="off" required>

  <div style="display:flex;gap:8px;margin-bottom:10px">
    <div style="flex:1">
      <div class="lbl">Amount (SOL)</div>
      <input name="amount" type="number" step="0.001" min="0.001" placeholder="0.000" style="margin-bottom:0" required>
    </div>
    <div style="display:flex;align-items:flex-end;padding-bottom:0">
      <a href="/withdraw/max" style="background:#1a2332;color:#4a6080;padding:10px 12px;border-radius:8px;text-decoration:none;font-size:12px;font-weight:600;white-space:nowrap">MAX</a>
    </div>
  </div>

  <div class="lbl">Wallet PIN (to sign transaction)</div>
  <input name="pin" type="password" placeholder="Your wallet PIN" autocomplete="current-password" required>

  <button type="submit" class="btn br">📤 Send SOL</button>
</form>

<div style="background:rgba(255,51,85,.07);border:1px solid rgba(255,51,85,.2);border-radius:8px;padding:10px 12px;font-size:11px;color:#ff8888;line-height:1.6">
  ⚠️ Double-check the recipient address. Solana transactions are irreversible.
</div>
<br>
<a href="/" class="btn bx">← Back to Dashboard</a>
</body></html>`;
}

// ── Settings page ─────────────────────────────────────────
function settingsPage(saved='', error='') {
  const keyMasked = runtimeClaudeKey
    ? runtimeClaudeKey.slice(0,10)+'•'.repeat(20)+runtimeClaudeKey.slice(-4)
    : '';
  const hasKey = !!runtimeClaudeKey;
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>⚙️ Settings</title><style>
*{box-sizing:border-box;margin:0;padding:0}body{background:#070a10;color:#d4e5ff;font-family:system-ui,sans-serif;font-size:13px;padding:12px;max-width:480px;margin:0 auto}
input,select{width:100%;background:#0d1117;border:1px solid #1a2332;border-radius:8px;padding:10px 12px;color:#d4e5ff;font-size:13px;font-family:inherit;margin-bottom:10px}
input:focus,select:focus{outline:none;border-color:#8b5cf6}
.btn{display:block;width:100%;padding:11px;border-radius:8px;border:none;font-size:13px;font-weight:700;cursor:pointer;text-align:center;text-decoration:none;font-family:inherit;margin-bottom:8px}
.bg{background:#8b5cf6;color:#fff}.br{background:#ff3355;color:#fff}.bx{background:#1a2332;color:#4a6080}
.card{background:#0d1117;border:1px solid #1a2332;border-radius:10px;padding:14px;margin-bottom:10px}
.lbl{font-size:11px;color:#4a6080;margin-bottom:5px;display:flex;justify-content:space-between;align-items:center}
.ok{background:rgba(0,232,122,.1);border:1px solid rgba(0,232,122,.3);border-radius:7px;padding:9px 12px;font-size:12px;color:#00e87a;margin-bottom:10px}
.err{background:rgba(255,51,85,.1);border:1px solid rgba(255,51,85,.3);border-radius:7px;padding:9px 12px;font-size:12px;color:#ff3355;margin-bottom:10px}
.sec-title{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#4a6080;margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid #1a2332}
h1{font-size:16px;font-weight:700;margin-bottom:10px}
.badge{font-size:10px;padding:2px 7px;border-radius:4px;font-weight:600}
.badge-ok{background:rgba(0,232,122,.15);color:#00e87a}
.badge-warn{background:rgba(255,176,32,.15);color:#ffb020}
a{color:#3b9eff;text-decoration:none}
hr{border:none;border-top:1px solid #1a2332;margin:14px 0}
</style></head><body>
<h1>🌕 Gem Hunter</h1>
${navBar('/settings')}
${saved?`<div class="ok">✅ ${saved}</div>`:''}
${error?`<div class="err">❌ ${error}</div>`:''}

<!-- API KEYS -->
<div class="card">
  <div class="sec-title">🔑 API Keys</div>

  <form method="POST" action="/settings/save-key">
    <div class="lbl">
      <span>Claude AI Key</span>
      <span class="badge ${hasKey?'badge-ok':'badge-warn'}">${hasKey?'✅ Active':'⚠️ Not set'}</span>
    </div>
    ${hasKey?`<div style="font-family:monospace;font-size:11px;color:#4a6080;background:#070a10;border-radius:6px;padding:8px 10px;margin-bottom:8px;word-break:break-all">${keyMasked}</div>`:''}
    <input name="claude_key" type="password" placeholder="sk-ant-api03-..." autocomplete="off">
    <div style="font-size:11px;color:#4a6080;margin-bottom:10px">Get a key at <a href="https://console.anthropic.com" target="_blank">console.anthropic.com ↗</a> · ~$0.10-0.50/day</div>
    <button type="submit" class="btn bg">💾 Save API Key</button>
  </form>

  ${hasKey?`<form method="POST" action="/settings/clear-key" style="margin-top:6px">
    <button type="submit" class="btn br" onclick="return confirm('Remove API key? Bot will use rule-based mode.')">🗑 Remove Key</button>
  </form>`:''}
</div>

<!-- BOT SETTINGS -->
<div class="card">
  <div class="sec-title">🤖 Bot Strategy</div>
  <form method="POST" action="/settings/save-bot">
    <div class="lbl">Mode</div>
    <select name="mode">
      <option value="paper" ${C.MODE==='paper'?'selected':''}>Paper Trading (no real money)</option>
      <option value="live"  ${C.MODE==='live'?'selected':''}>⚡ Live Trading (real SOL)</option>
    </select>

    <div class="lbl">Position Size (SOL per trade)</div>
    <input name="pos_sol" type="number" step="0.01" min="0.01" value="${C.POS_SOL}">

    <div class="lbl">Max Open Positions</div>
    <input name="max_pos" type="number" min="1" max="20" value="${C.MAX_POS}">

    <div class="lbl">Min Gem Score (0-100)</div>
    <input name="min_score" type="number" min="40" max="90" value="${C.MIN_SCORE}">

    <div class="lbl">Stop Loss %</div>
    <input name="stop_pct" type="number" min="10" max="80" value="${C.STOP_PCT}">

    <div class="lbl">Trailing Stop %</div>
    <input name="trail_pct" type="number" min="10" max="60" value="${C.TRAIL_PCT}">

    <div class="lbl">Max Hold (hours)</div>
    <input name="max_hold" type="number" min="1" max="720" value="${C.MAX_HOLD}">

    <div class="lbl">Min Market Cap $</div>
    <input name="min_mc" type="number" value="${C.MIN_MC}">

    <div class="lbl">Max Market Cap $</div>
    <input name="max_mc" type="number" value="${C.MAX_MC}">

    <div class="lbl">Scan Interval (seconds)</div>
    <input name="interval" type="number" min="10" max="300" value="${C.INTERVAL}">

    <button type="submit" class="btn bg">💾 Save Strategy</button>
  </form>
</div>

<!-- WALLET INFO -->
<div class="card">
  <div class="sec-title">🔐 Wallet</div>
  <div class="lbl">
    <span>Address</span>
    <span class="badge ${walletLoaded?'badge-ok':'badge-warn'}">${walletLoaded?'✅ Unlocked':'🔒 Locked'}</span>
  </div>
  <div style="font-family:monospace;font-size:11px;color:#4a6080;word-break:break-all;margin-bottom:10px">${walletPubkey||'—'}</div>
  <div class="lbl">
    <span>Balance</span>
  </div>
  <div style="font-size:16px;font-weight:700;color:#00e87a;font-family:monospace;margin-bottom:4px">${solBalance.toFixed(4)} ◎</div>
  <div style="font-size:11px;color:#4a6080">≈ $${(solBalance*solPrice).toFixed(2)}</div>
  <hr>
  <a href="/deposit" class="btn bx" style="display:block;text-align:center;margin-bottom:6px">📥 Deposit SOL</a>
  <a href="/withdraw" class="btn bx" style="display:block;text-align:center;margin-bottom:6px">📤 Withdraw SOL</a>
  <a href="/lock" class="btn bx" style="display:block;text-align:center;color:#ff3355">🔒 Lock Wallet</a>
</div>

<!-- DANGER ZONE -->
<div class="card" style="border-color:rgba(255,51,85,.3)">
  <div class="sec-title" style="color:#ff3355">⚠️ Danger Zone</div>
  <form method="POST" action="/settings/reset-brain" onsubmit="return confirm('Reset AI brain? All learning history will be lost.')">
    <button type="submit" class="btn br">🧠 Reset AI Brain</button>
  </form>
</div>

<a href="/" class="btn bx">← Back to Dashboard</a>
</body></html>`;
}

function parseBody(req) {
  return new Promise((res,rej) => {
    let body='';
    req.on('data',d=>{body+=d;if(body.length>10000)rej(new Error('body too large'));});
    req.on('end',()=>{
      try {
        const params={};
        body.split('&').forEach(pair=>{
          const [k,v]=pair.split('=');
          if(k)params[decodeURIComponent(k.trim())]=decodeURIComponent((v||'').trim().replace(/\+/g,' '));
        });
        res(params);
      } catch {res({});}
    });
    req.on('error',rej);
  });
}

function getSessionFromReq(req) {
  const cookies=req.headers.cookie||'';
  const match=cookies.match(/session=([a-f0-9]+)/);
  return match?match[1]:'';
}

function setCookieHeader(tok) {
  return `session=${tok}; HttpOnly; SameSite=Strict; Max-Age=${4*3600}; Path=/`;
}

const server = http.createServer(async (req, res) => {
  const url    = req.url.split('?')[0];
  const ip     = req.headers['x-forwarded-for']?.split(',')[0]||req.socket.remoteAddress||'?';
  const method = req.method;
  const tok    = getSessionFromReq(req);
  const authed = validSession(tok);

  // ── Auth endpoints ─────────────────────────────────────
  if (url==='/auth/unlock' && method==='POST') {
    if (rateLimit(ip, 5, 60000)) { res.writeHead(429); res.end('Too many attempts'); return; }
    const body=await parseBody(req);
    if (C.DASH_PIN && body.dashpin !== C.DASH_PIN) {
      res.writeHead(200,{'Content-Type':'text/html'});
      res.end(loginPage('Wrong dashboard PIN'));return;
    }
    try {
      await walletUnlock(body.pin||'');
      const newTok=createSession();
      res.writeHead(302,{'Set-Cookie':setCookieHeader(newTok),'Location':'/'});res.end();
    } catch(e) {
      res.writeHead(200,{'Content-Type':'text/html'});
      res.end(loginPage(e.message.includes('Wrong')?'Wrong wallet PIN':'Error: '+e.message.slice(0,60)));
    }
    return;
  }

  if (url==='/auth/create' && method==='POST') {
    if (rateLimit(ip, 5, 60000)) { res.writeHead(429); res.end('Too many attempts'); return; }
    const body=await parseBody(req);
    if (C.DASH_PIN && body.dashpin !== C.DASH_PIN) { res.writeHead(200,{'Content-Type':'text/html'});res.end(loginPage('Wrong dashboard PIN'));return; }
    if (!body.pin||body.pin.length<6) { res.writeHead(200,{'Content-Type':'text/html'});res.end(loginPage('PIN must be at least 6 characters'));return; }
    if (body.pin!==body.pin2) { res.writeHead(200,{'Content-Type':'text/html'});res.end(loginPage('PINs do not match'));return; }
    try {
      await walletCreate(body.pin);
      const newTok=createSession();
      res.writeHead(302,{'Set-Cookie':setCookieHeader(newTok),'Location':'/'});res.end();
    } catch(e) { res.writeHead(200,{'Content-Type':'text/html'});res.end(loginPage('Error: '+e.message.slice(0,60))); }
    return;
  }

  if (url==='/auth/import' && method==='POST') {
    if (rateLimit(ip, 5, 60000)) { res.writeHead(429); res.end('Too many attempts'); return; }
    const body=await parseBody(req);
    if (C.DASH_PIN && body.dashpin !== C.DASH_PIN) { res.writeHead(200,{'Content-Type':'text/html'});res.end(loginPage('Wrong dashboard PIN'));return; }
    if (!body.privkey||!body.pin||body.pin.length<6) { res.writeHead(200,{'Content-Type':'text/html'});res.end(loginPage('Private key and PIN (min 6 chars) required'));return; }
    try {
      await walletImport(body.privkey, body.pin);
      const newTok=createSession();
      res.writeHead(302,{'Set-Cookie':setCookieHeader(newTok),'Location':'/'});res.end();
    } catch(e) { res.writeHead(200,{'Content-Type':'text/html'});res.end(loginPage('Import failed: '+e.message.slice(0,60))); }
    return;
  }

  // ── Login page (no session) ────────────────────────────
  if (!authed) {
    res.writeHead(200,{'Content-Type':'text/html'});
    res.end(loginPage());
    return;
  }

  // ── Authenticated routes ───────────────────────────────
  if (url==='/start') {
    if (!running) {running=true;startedAt=Date.now();log('info','START',`${C.MODE} mode`);runCycle();}
    res.writeHead(302,{Location:'/'});res.end();return;
  }
  if (url==='/stop') {
    running=false;clearTimeout(nextTimer);log('info','STOP','via dashboard');
    res.writeHead(302,{Location:'/'});res.end();return;
  }
  if (url==='/lock') {
    sessions.delete(tok);
    walletLoaded=false;walletSK=null;walletPubkey='';
    if(running){running=false;clearTimeout(nextTimer);log('info','STOP','wallet locked');}
    res.writeHead(302,{'Set-Cookie':'session=; Max-Age=0; Path=/','Location':'/'});res.end();return;
  }
  if (url.startsWith('/exit/')) {
    const i=parseInt(url.split('/')[2]);
    if (positions[i]) {const p=positions[i];const pct=p.entry?(p.current-p.entry)/p.entry*100:0;await doExit(i,p,pct,'Manual exit');}
    res.writeHead(302,{Location:'/'});res.end();return;
  }

  // ── DEPOSIT routes ────────────────────────────────────
  if (url==='/deposit') {
    await refreshBalance();
    res.writeHead(200,{'Content-Type':'text/html'});res.end(depositPage());return;
  }
  if (url==='/deposit/copy') {
    // Redirect with address in clipboard hint
    res.writeHead(302,{Location:'/deposit?copied=1'});res.end();return;
  }
  if (url==='/deposit/refresh') {
    await refreshBalance();
    res.writeHead(302,{Location:'/deposit'});res.end();return;
  }

  // ── WITHDRAW routes ───────────────────────────────────
  if (url==='/withdraw') {
    await refreshBalance();
    res.writeHead(200,{'Content-Type':'text/html'});res.end(withdrawPage());return;
  }
  if (url==='/withdraw/max') {
    // Return page with max amount pre-filled via query
    await refreshBalance();
    const maxAmt=Math.max(0,solBalance-0.002).toFixed(4);
    res.writeHead(200,{'Content-Type':'text/html'});res.end(withdrawPage().replace('placeholder="0.000"',`value="${maxAmt}"`));return;
  }
  if (url==='/withdraw/send' && method==='POST') {
    if (rateLimit(ip,3,60000)){res.writeHead(429);res.end('Too many attempts');return;}
    const body=await parseBody(req);
    const to=body.to?.trim(), amt=parseFloat(body.amount), pin=body.pin||'';
    if (!to||to.length<32){res.writeHead(200,{'Content-Type':'text/html'});res.end(withdrawPage('','Invalid recipient address'));return;}
    if (!amt||amt<=0||amt>solBalance-0.002){res.writeHead(200,{'Content-Type':'text/html'});res.end(withdrawPage('','Invalid amount or insufficient balance'));return;}
    if (!pin){res.writeHead(200,{'Content-Type':'text/html'});res.end(withdrawPage('','Enter your wallet PIN'));return;}
    if (!walletHasFile()){res.writeHead(200,{'Content-Type':'text/html'});res.end(withdrawPage('','No wallet found'));return;}
    try {
      log('info','WITHDRAW',`${amt} SOL → ${to.slice(0,8)}...`);
      const txSig=await sendSOL(to, amt, pin);
      await refreshBalance();
      log('info','WITHDRAW OK',`tx:${txSig.slice(0,16)}...`);
      res.writeHead(200,{'Content-Type':'text/html'});res.end(withdrawPage(txSig,''));
    } catch(e) {
      const msg=e.message.includes('Wrong PIN')||e.message.includes('Wrong wallet')?'Wrong wallet PIN':e.message.slice(0,80);
      log('warn','WITHDRAW FAIL',msg);
      res.writeHead(200,{'Content-Type':'text/html'});res.end(withdrawPage('',msg));
    }
    return;
  }

  // ── SETTINGS routes ───────────────────────────────────
  if (url==='/settings') {
    res.writeHead(200,{'Content-Type':'text/html'});res.end(settingsPage());return;
  }
  if (url==='/settings/save-key' && method==='POST') {
    const body=await parseBody(req);
    const key=(body.claude_key||'').trim();
    if (key&&!key.startsWith('sk-ant-')){res.writeHead(200,{'Content-Type':'text/html'});res.end(settingsPage('','Key must start with sk-ant-'));return;}
    if (key) {
      runtimeClaudeKey=key;
      C.CLAUDE_KEY=key;
      log('info','SETTINGS','Claude API key updated');
    }
    res.writeHead(200,{'Content-Type':'text/html'});res.end(settingsPage('API key saved ✅'));return;
  }
  if (url==='/settings/clear-key' && method==='POST') {
    runtimeClaudeKey=''; C.CLAUDE_KEY='';
    log('info','SETTINGS','Claude API key removed');
    res.writeHead(200,{'Content-Type':'text/html'});res.end(settingsPage('API key removed — bot using rule-based mode'));return;
  }
  if (url==='/settings/save-bot' && method==='POST') {
    const body=await parseBody(req);
    // Update config at runtime (survives until next Railway restart)
    if (body.pos_sol)   C.POS_SOL   = Math.max(0.001, parseFloat(body.pos_sol)||C.POS_SOL);
    if (body.max_pos)   C.MAX_POS   = Math.max(1, parseInt(body.max_pos)||C.MAX_POS);
    if (body.min_score) C.MIN_SCORE = Math.max(40, Math.min(90, parseInt(body.min_score)||C.MIN_SCORE));
    if (body.stop_pct)  C.STOP_PCT  = Math.max(10, parseFloat(body.stop_pct)||C.STOP_PCT);
    if (body.trail_pct) C.TRAIL_PCT = Math.max(10, parseFloat(body.trail_pct)||C.TRAIL_PCT);
    if (body.max_hold)  C.MAX_HOLD  = Math.max(1,  parseInt(body.max_hold)||C.MAX_HOLD);
    if (body.min_mc)    C.MIN_MC    = Math.max(0,   parseInt(body.min_mc)||C.MIN_MC);
    if (body.max_mc)    C.MAX_MC    = Math.max(1000,parseInt(body.max_mc)||C.MAX_MC);
    if (body.interval)  C.INTERVAL  = Math.max(10,  parseInt(body.interval)||C.INTERVAL);
    if (body.mode&&(body.mode==='paper'||body.mode==='live')) {
      if (body.mode==='live'&&!walletLoaded){res.writeHead(200,{'Content-Type':'text/html'});res.end(settingsPage('','Unlock your wallet before switching to live mode'));return;}
      C.MODE=body.mode;
    }
    log('info','SETTINGS',`Bot config updated: mode=${C.MODE} posSOL=${C.POS_SOL} maxPos=${C.MAX_POS} score≥${C.MIN_SCORE}`);
    res.writeHead(200,{'Content-Type':'text/html'});res.end(settingsPage('Strategy saved ✅'));return;
  }
  if (url==='/settings/reset-brain' && method==='POST') {
    brain={totalTrades:0,lifetimeWins:0,lifetimeLosses:0,lifetimePnl:0,epoch:0,
      patterns:{winBSR:[],loseBSR:[],winScore:[],loseScore:[],winAge:[],loseAge:[],winHold:[],loseHold:[]},
      evolvedParams:{minBSR:1.1,minScore:C.MIN_SCORE,kellyFraction:0.5},
      insights:[],hallOfFame:[],hallOfShame:[]};
    saveBrain();
    log('info','BRAIN RESET','All learning history cleared');
    res.writeHead(200,{'Content-Type':'text/html'});res.end(settingsPage('Brain reset ✅'));return;
  }

  // ── API state ─────────────────────────────────────────
  if (url==='/api/state') {
    res.writeHead(200,{'Content-Type':'application/json'});
    res.end(JSON.stringify({
      wallet:{address:walletPubkey,loaded:walletLoaded,balance:solBalance,mode:C.MODE},
      running,cycle,regime,solPrice,
      portfolio:{balance:C.MODE==='paper'?paperBal:solBalance*solPrice,positions:positions.length,trades:trades.length,wins,losses},
      brain:{epoch:brain.epoch,totalTrades:brain.totalTrades,evolvedParams:brain.evolvedParams},
      recentTrades:trades.slice(-10),
      logs:logs.slice(0,30)
    },null,2));
    return;
  }

  res.writeHead(200,{'Content-Type':'text/html'});
  res.end(dashPage());
});

// ═══════════════════════════════════════════════════════════
//  STARTUP
// ═══════════════════════════════════════════════════════════
server.listen(C.PORT, () => {
  console.log('\n╔══════════════════════════════════════════════╗');
  console.log('║    🌕 GEM HUNTER — SECURE BOT v2            ║');
  console.log('╚══════════════════════════════════════════════╝\n');
  console.log(`  Mode:        ${C.MODE.toUpperCase()}`);
  console.log(`  AI:          ${C.CLAUDE_KEY?'✅ Claude active':'⚠️  No key — rule-based'}`);
  console.log(`  Dashboard:   http://localhost:${C.PORT}`);
  console.log(`  PIN protect: ${C.DASH_PIN?'✅ Dashboard PIN set':'⚠️  No DASHBOARD_PIN set — anyone can access'}`);
  console.log(`  Wallet:      ${walletHasFile()?'✅ Encrypted wallet found — unlock to trade':'⚠️  No wallet — create one on the dashboard'}`);
  console.log(`  Encryption:  AES-256-GCM + PBKDF2 (${PBKDF2_ITER.toLocaleString()} iterations)\n`);
  console.log(`  Open dashboard → enter your wallet PIN to start trading\n`);
  log('info','BOOT',`port=${C.PORT} mode=${C.MODE} ai=${!!C.CLAUDE_KEY} pin=${!!C.DASH_PIN} wallet=${walletHasFile()}`);
});

process.on('SIGINT', ()=>{ log('info','SHUTDOWN','SIGINT'); walletSK=null; process.exit(0); });
process.on('SIGTERM',()=>{ log('info','SHUTDOWN','SIGTERM');walletSK=null; process.exit(0); });
process.on('uncaughtException',e=>log('warn','UNCAUGHT',e.message));
