#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════
//  GEM HUNTER — Node.js 24/7 Server Bot
//  Usage: node bot.js
//  Dashboard: http://localhost:3000
// ═══════════════════════════════════════════════════════════
'use strict';
const fs   = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

// ── Config ──────────────────────────────────────────────
const C = {
  CLAUDE_KEY : process.env.CLAUDE_API_KEY  || '',
  PUBKEY     : process.env.WALLET_PUBKEY   || '',
  MODE       : process.env.MODE            || 'paper',
  INTERVAL   : +( process.env.SCAN_INTERVAL || 20),
  POS_SOL    : +(process.env.POS_SIZE_SOL  || 0.05),
  MAX_POS    : +( process.env.MAX_POSITIONS || 5),
  MIN_SCORE  : +( process.env.MIN_SCORE    || 62),
  STOP_PCT   : +(process.env.STOP_LOSS_PCT || 45),
  TRAIL_PCT  : +(process.env.TRAIL_STOP_PCT|| 35),
  MAX_HOLD   : +( process.env.MAX_HOLD_HOURS|| 168),
  MIN_MC     : +( process.env.MIN_MC       || 15000),
  MAX_MC     : +( process.env.MAX_MC       || 300000),
  MAX_RISK   : +( process.env.MAX_RISK     || 40),
  PORT       : +( process.env.PORT         || 3000),
  DATA       : process.env.DATA_DIR        || './data',
  START_BAL  : +(process.env.PAPER_BAL     || 100),
  ANTIRUG    : process.env.ANTIRUG !== 'false',
  RPC        : process.env.RPC_URL || 'https://api.mainnet-beta.solana.com',
};

const JUP_Q   = 'https://quote-api.jup.ag/v6/quote';
const DEX_API = 'https://api.dexscreener.com';
const CLAUDE  = 'https://api.anthropic.com/v1/messages';
const SOL_MINT= 'So11111111111111111111111111111111111111112';
const MODEL   = 'claude-sonnet-4-6';

if (!fs.existsSync(C.DATA)) fs.mkdirSync(C.DATA, {recursive:true});
const BRAIN_F  = path.join(C.DATA,'brain.json');
const TRADES_F = path.join(C.DATA,'trades.json');
const LOG_F    = path.join(C.DATA,'bot.log');

// ── State ─────────────────────────────────────────────
let solPrice=170, solBal=0, running=false;
let paperBal=C.START_BAL, positions=[], trades=loadJ(TRADES_F)||[];
let wins=0,losses=0,streak=0,cycle=0,startedAt=null;
let regime='neutral', analyzing=new Set(), pyrs={}, nextTimer=null;
const logs=[]; // ring buffer for dashboard

trades.forEach(t => t.pnl>0 ? wins++ : losses++);

// ── Logging ──────────────────────────────────────────
function log(type,label,detail=''){
  const ts=new Date().toISOString();
  const line=`[${ts}] [${type.toUpperCase().padEnd(4)}] ${label}${detail?' — '+detail:''}`;
  console.log(line);
  try{ fs.appendFileSync(LOG_F,line+'\n'); }catch{}
  logs.unshift({ts,type,label,detail});
  if(logs.length>200) logs.pop();
}

// ── Persistence ───────────────────────────────────────
function loadJ(f){ try{return JSON.parse(fs.readFileSync(f,'utf8'));}catch{return null;} }
function saveJ(f,d){ try{fs.writeFileSync(f,JSON.stringify(d,null,2));}catch(e){log('warn','SAVE',e.message);} }

// ── Brain ─────────────────────────────────────────────
let brain = loadJ(BRAIN_F) || {
  totalTrades:0,lifetimeWins:0,lifetimeLosses:0,lifetimePnl:0,epoch:0,
  patterns:{winBSR:[],loseBSR:[],winScore:[],loseScore:[],winAge:[],loseAge:[],winHold:[],loseHold:[]},
  evolvedParams:{minBSR:1.1,minScore:C.MIN_SCORE,stopLoss:C.STOP_PCT,trailStop:C.TRAIL_PCT,kellyFraction:0.5},
  insights:[],hallOfFame:[],hallOfShame:[]
};

const avg = a => a.length ? a.reduce((s,v)=>s+v,0)/a.length : null;

function learnFromTrade(trade,meta){
  if(!meta)return;
  const w=trade.pnl>0,pre=w?'win':'lose';
  const push=(a,v)=>{a.push(v);if(a.length>100)a.shift();};
  push(brain.patterns[pre+'BSR'],  meta.bsr||1);
  push(brain.patterns[pre+'Score'],meta.score||50);
  push(brain.patterns[pre+'Age'],  meta.age||48);
  if(trade.closedAt&&trade.openedAt) push(brain.patterns[pre+'Hold'],(trade.closedAt-trade.openedAt)/3600000);
  brain.totalTrades++; brain.lifetimePnl+=trade.pnl||0;
  if(w) brain.lifetimeWins++; else brain.lifetimeLosses++;
  const s={token:trade.token,pct:trade.pct||0,pnl:trade.pnl||0,bsr:meta.bsr,age:meta.age,score:meta.score};
  if(w){brain.hallOfFame.push(s);brain.hallOfFame.sort((a,b)=>b.pnl-a.pnl);if(brain.hallOfFame.length>5)brain.hallOfFame.pop();}
  else {brain.hallOfShame.push(s);brain.hallOfShame.sort((a,b)=>a.pnl-b.pnl);if(brain.hallOfShame.length>5)brain.hallOfShame.pop();}
  if(brain.totalTrades%5===0){evolve();if(C.CLAUDE_KEY)requestInsight().catch(()=>{});}
  saveJ(BRAIN_F,brain);
}

function evolve(){
  const p=brain.patterns,ep=brain.evolvedParams;
  if(brain.totalTrades<4)return;
  const wB=avg(p.winBSR),lB=avg(p.loseBSR);
  if(wB&&lB) ep.minBSR=Math.max(1.0,Math.min(3.0,wB*0.7+ep.minBSR*0.3));
  const wS=avg(p.winScore);
  if(wS) ep.minScore=Math.round(Math.max(45,Math.min(80,wS*0.75+ep.minScore*0.25)));
  const wr=brain.totalTrades>0?brain.lifetimeWins/brain.totalTrades:0.45;
  ep.kellyFraction=Math.max(0.25,Math.min(0.75,0.35+wr*0.4));
  brain.epoch++;
  log('info',`🧬 EPOCH ${brain.epoch}`,`BSR→${ep.minBSR.toFixed(2)} score→${ep.minScore} kelly→${(ep.kellyFraction*100).toFixed(0)}%`);
  saveJ(BRAIN_F,brain);
}

async function requestInsight(){
  if(!C.CLAUDE_KEY||brain.totalTrades<3)return;
  const p=brain.patterns,ep=brain.evolvedParams;
  const prompt=`You are an AI trading bot. ${brain.totalTrades} trades, WR ${(brain.lifetimeWins/brain.totalTrades*100).toFixed(1)}%. Win BSR ${avg(p.winBSR)?.toFixed(2)||'n/a'}x vs loss ${avg(p.loseBSR)?.toFixed(2)||'n/a'}x. Win score ${avg(p.winScore)?.toFixed(0)||'n/a'} vs loss ${avg(p.loseScore)?.toFixed(0)||'n/a'}. Best: ${brain.hallOfFame.slice(0,2).map(t=>t.token+' +'+t.pct.toFixed(0)+'%').join(', ')||'none'}. Write 2 sentences of genuine insight.`;
  try{
    const d=await claudeCall(prompt,150);
    const txt=d?.content?.find(b=>b.type==='text')?.text||'';
    if(txt.length>20){brain.insights.unshift({text:txt,count:brain.totalTrades,ts:Date.now()});if(brain.insights.length>10)brain.insights.pop();saveJ(BRAIN_F,brain);}
    log('info','🧠 INSIGHT',txt.slice(0,100));
  }catch{}
}

function learnedCtx(){
  const p=brain.patterns,ep=brain.evolvedParams;
  if(brain.totalTrades<2)return'No trade history yet.';
  const lines=[`BRAIN: ${brain.totalTrades} trades, epoch ${brain.epoch}, P&L $${brain.lifetimePnl.toFixed(2)}`];
  if(p.winBSR.length) lines.push(`Win BSR ${avg(p.winBSR).toFixed(2)}x vs lose ${avg(p.loseBSR)?.toFixed(2)||'?'}x → min ${ep.minBSR.toFixed(2)}x`);
  if(p.winScore.length) lines.push(`Win score ${avg(p.winScore).toFixed(0)} vs lose ${avg(p.loseScore)?.toFixed(0)||'?'} → threshold ${ep.minScore}`);
  if(brain.insights.length) lines.push(`Insight: "${brain.insights[0].text.slice(0,140)}"`);
  return lines.join('\n');
}

// ── HTTP helpers ──────────────────────────────────────
function get(url){
  return new Promise((res,rej)=>{
    const req=https.get(url,{headers:{Accept:'application/json'}},r=>{
      let d='';r.on('data',c=>d+=c);
      r.on('end',()=>{try{res(JSON.parse(d));}catch(e){rej(new Error('parse:'+d.slice(0,60)));}});
    });
    req.on('error',rej);
    req.setTimeout(15000,()=>{req.destroy();rej(new Error('timeout'));});
  });
}

function post(url,body,hdrs={}){
  return new Promise((res,rej)=>{
    const s=JSON.stringify(body);
    const u=new URL(url);
    const req=https.request({hostname:u.hostname,path:u.pathname+u.search,method:'POST',
      headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(s),...hdrs}},r=>{
      let d='';r.on('data',c=>d+=c);
      r.on('end',()=>{try{res(JSON.parse(d));}catch(e){rej(new Error('parse:'+d.slice(0,60)));}});
    });
    req.on('error',rej);
    req.setTimeout(30000,()=>{req.destroy();rej(new Error('timeout'));});
    req.write(s);req.end();
  });
}

function claudeCall(prompt,maxT=200){
  if(!C.CLAUDE_KEY)return Promise.resolve(null);
  return post(CLAUDE,{model:MODEL,max_tokens:maxT,messages:[{role:'user',content:prompt}]},
    {'x-api-key':C.CLAUDE_KEY,'anthropic-version':'2023-06-01'});
}

function rpc(method,params){
  return post(C.RPC,{jsonrpc:'2.0',id:1,method,params}).then(d=>{if(d.error)throw new Error(d.error.message);return d.result;});
}

// ── Scoring ───────────────────────────────────────────
function score(p){
  const g1h=p.priceChange?.h1||0,g5m=p.priceChange?.m5||0,g6h=p.priceChange?.h6||0;
  const v5m=p.volume?.m5||0,v1h=p.volume?.h1||0,liq=p.liquidity?.usd||0,mc=p.fdv||p.marketCap||1;
  const b1h=p.txns?.h1?.buys||0,s1h=p.txns?.h1?.sells||1,b5m=p.txns?.m5?.buys||0,s5m=p.txns?.m5?.sells||1;
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

function kelly(base,conf){
  const ep=brain.evolvedParams,kf=ep.kellyFraction||0.5;
  const wr=(wins+losses>4)?wins/(wins+losses):((brain.lifetimeWins+brain.lifetimeLosses>10)?brain.lifetimeWins/(brain.lifetimeWins+brain.lifetimeLosses):0.45);
  const b=2.5/0.35,raw=Math.max(0,(b*wr-(1-wr))/b);
  const wrM=0.2+wr*1.6,cM=Math.max(0.5,Math.min(1.6,(conf-40)/50+0.5)),kA=0.6+raw*kf*2;
  return Math.max(base*0.5,Math.min(base*2.5,base*wrM*cM*kA*Math.pow(0.75,Math.min(streak,4))));
}

function fmt(n){return n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3).toFixed(0)+'K':n.toFixed(0);}

// ── Market data ───────────────────────────────────────
async function fetchPrice(){
  try{const d=await get(`https://price.jup.ag/v6/price?ids=${SOL_MINT}`);const p=d?.data?.[SOL_MINT]?.price;if(p)solPrice=p;}catch{}
}

async function fetchRunners(){
  let pairs=[];
  try{
    const b=await get(`${DEX_API}/token-boosts/top/v1`);
    const mints=(Array.isArray(b)?b:[]).filter(t=>t.chainId==='solana').slice(0,25).map(t=>t.tokenAddress).join(',');
    if(mints){const d=await get(`${DEX_API}/latest/dex/tokens/${mints}`);pairs=(d.pairs||[]).filter(p=>p.chainId==='solana');}
  }catch{}
  if(!pairs.length){try{const d=await get(`${DEX_API}/latest/dex/search?q=solana+meme`);pairs=(d.pairs||[]).filter(p=>p.chainId==='solana');}catch{}}
  const ep=brain.totalTrades>=4?brain.evolvedParams:{};
  const bsr=ep.minBSR||1.1;
  return pairs.filter(p=>{
    const liq=p.liquidity?.usd||0,mc=p.fdv||p.marketCap||0,g1h=p.priceChange?.h1||0;
    const b=p.txns?.h1?.buys||0,s=p.txns?.h1?.sells||1,vmr=(p.volume?.h1||0)/(mc||1);
    const age=p.pairCreatedAt?(Date.now()-p.pairCreatedAt)/3600000:999;
    if(liq<5000||liq>600000||mc<C.MIN_MC||mc>C.MAX_MC*3||g1h<10||b/s<bsr||age>240||vmr<0.05)return false;
    if(regime==='bear'&&(g1h<40||b/s<1.8||vmr<0.2))return false;
    return true;
  }).map(p=>({p,s:score(p)})).sort((a,b)=>b.s-a.s).slice(0,10).map(x=>x.p);
}

function updateRegime(runners){
  if(!runners.length)return;
  const a=runners.reduce((s,r)=>s+(r.priceChange?.h1||0),0)/runners.length;
  const b=runners.filter(r=>(r.priceChange?.h1||0)>30).length;
  regime=a>40&&b>runners.length*0.6?'bull':a<10||b<runners.length*0.2?'bear':'neutral';
}

async function risk(mint){
  let r=20;
  try{const d=await rpc('getAccountInfo',[mint,{encoding:'jsonParsed'}]);if(d?.value?.data?.parsed){const i=d.value.data.parsed.info;if(i.mintAuthority)r+=20;if(i.freezeAuthority)r+=18;}}catch{}
  try{const d=await get(`https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses=${mint}`);const i=d?.result?.[mint];if(i){if(i.is_honeypot==='1')r+=55;if(parseFloat(i.sell_tax||0)>15)r+=10;}}catch{}
  return Math.min(100,r);
}

async function aiDecide(p,rsk){
  const sym=p.baseToken?.symbol||'?',mc=p.fdv||p.marketCap||0;
  const sc=score(p);
  const ep=brain.totalTrades>=4?brain.evolvedParams:{};
  const eff=ep.minScore||C.MIN_SCORE;
  if(!C.CLAUDE_KEY){const buy=sc>=eff&&!(streak>=2&&sc<78);return{action:buy?'BUY':'SKIP',confidence:sc,positionMultiplier:sc>=80?1.4:1.0,reasoning:`[no-ai] score ${sc}/${eff}`};}
  const g1h=(p.priceChange?.h1||0).toFixed(0),vmr=((p.volume?.h1||0)/(mc||1)).toFixed(2);
  const b=p.txns?.h1?.buys||0,s=p.txns?.h1?.sells||1,age=p.pairCreatedAt?((Date.now()-p.pairCreatedAt)/3600000).toFixed(1)+'h':'?';
  const prompt=`You are a low-cap gem hunter. Goal: $15K-$300K MC tokens that can reach $1M+.\n\n${learnedCtx()}\n\nTOKEN: ${sym} | MC: $${fmt(mc)} | Age: ${age} | Risk: ${rsk}/100 | Score: ${sc}/100\nVol/MC: ${vmr}x | 1h: +${g1h}% | BSR: ${(b/s).toFixed(2)}x | Regime: ${regime.toUpperCase()}\nPositions: ${positions.length}/${C.MAX_POS} | Streak: ${streak}${streak>=2?`\nCAUTION: require score ≥ 78`:''}\n\nReply ONLY JSON: {"action":"BUY","confidence":78,"positionMultiplier":1.2,"reasoning":"..."} or {"action":"SKIP",...}`;
  try{
    const d=await claudeCall(prompt,200);
    const txt=d?.content?.find(b=>b.type==='text')?.text||'';
    const parsed=JSON.parse(txt.replace(/```json|```/g,'').trim());
    return{...parsed,reasoning:parsed.reasoning||parsed.reason||'ok'};
  }catch{return{action:sc>=eff?'BUY':'SKIP',confidence:sc,positionMultiplier:1.0,reasoning:'[fallback]'};}
}

async function aiExit(pos,pct,trail,hrs,mult){
  if(!C.CLAUDE_KEY)return{exit:trail>40&&mult<5,reason:'demo'};
  try{
    const d=await claudeCall(`Exit check: ${pos.token} at ${mult.toFixed(1)}x (+${pct.toFixed(0)}%), trail -${trail.toFixed(0)}%, held ${hrs.toFixed(1)}h. Partials: 10x=${!!pos.p10} 50x=${!!pos.p50}. Goal 100x+. Only exit if momentum broken. {"exit":false,"reason":"..."} or {"exit":true,"reason":"..."}`,100);
    const txt=d?.content?.find(b=>b.type==='text')?.text||'{}';
    return JSON.parse(txt.replace(/```json|```/g,'').trim());
  }catch{return{exit:false,reason:'err'};}
}

// ── Trading ───────────────────────────────────────────
async function doBuy(p,dec,rsk){
  const sym=p.baseToken?.symbol||'?',mint=p.baseToken?.address||'';
  const price=parseFloat(p.priceUsd||0)||(solPrice*1e-6);
  const posSOL=kelly(C.POS_SOL,dec.confidence)*(dec.positionMultiplier||1);
  const cost=Math.min(posSOL*solPrice,paperBal*0.85);
  if(cost<0.5){log('skip',`LOW BAL ${sym}`,'');return;}
  paperBal-=cost;
  const mc=p.fdv||p.marketCap||0;
  const meta={bsr:+(p.txns?.h1?(p.txns.h1.buys/(p.txns.h1.sells||1)):1).toFixed(2),g1h:p.priceChange?.h1||0,age:p.pairCreatedAt?(Date.now()-p.pairCreatedAt)/3600000:48,mc,liq:p.liquidity?.usd||0,score:score(p),regime};
  positions.push({token:sym,mint,entry:price,current:price,size:cost,sol:posSOL,aiScore:dec.confidence,risk:rsk,openedAt:Date.now(),peak:price,p10:false,p50:false,p100:false,meta});
  pyrs[mint]=0;
  log('buy',`BUY ${sym}`,`$${cost.toFixed(2)} · score ${dec.confidence} · ${(dec.reasoning||'').slice(0,70)}`);
}

async function doPartial(i,p,pct,frac,label){
  const ps=p.size*frac,pp=ps*pct/100;
  paperBal+=ps+pp;p.size-=ps;
  log('sell',`${label}: ${p.token}`,`+$${pp.toFixed(2)} rem $${p.size.toFixed(2)}`);
}

async function doExit(i,p,pct,reason){
  const pnl=p.size*pct/100;
  paperBal+=p.size+pnl;
  const t={token:p.token,entry:p.entry,exit:p.current,pnl,pct,size:p.size,openedAt:p.openedAt,closedAt:Date.now()};
  positions.splice(i,1);trades.push(t);saveJ(TRADES_F,trades);
  if(pnl>0){wins++;streak=0;}else{losses++;streak++;}
  learnFromTrade(t,p.meta);
  log('sell',`EXIT ${p.token}`,`${reason} · P&L ${pnl>=0?'+':''}$${pnl.toFixed(2)} (${pct.toFixed(0)}%)`);
}

async function updatePrices(){
  for(const p of positions){
    try{const d=await get(`${DEX_API}/latest/dex/tokens/${p.mint}`);const pp=(d.pairs||[]).find(x=>x.chainId==='solana');if(pp){const n=parseFloat(pp.priceUsd||0);if(n>0){p.current=n;if(n>p.peak)p.peak=n;}}}catch{}
    await new Promise(r=>setTimeout(r,200));
  }
}

async function checkExits(){
  const sl=regime==='bear'?Math.round(C.STOP_PCT*.7):C.STOP_PCT;
  const ts=regime==='bear'?Math.round(C.TRAIL_PCT*.7):C.TRAIL_PCT;
  for(let i=positions.length-1;i>=0;i--){
    const p=positions[i],pct=p.entry?(p.current-p.entry)/p.entry*100:0;
    const trail=p.peak?(p.peak-p.current)/p.peak*100:0,hrs=(Date.now()-p.openedAt)/3600000,mult=p.current/p.entry;
    if(!p.p10&&mult>=10){p.p10=true;await doPartial(i,p,pct,.20,'🚀 10x');continue;}
    if(!p.p50&&mult>=50){p.p50=true;await doPartial(i,p,pct,.20,'💎 50x');continue;}
    if(!p.p100&&mult>=100){p.p100=true;await doPartial(i,p,pct,.20,'🌕 100x');continue;}
    const n=pyrs[p.mint]||0;
    if(n<3&&regime!=='bear'){const mst=[3,10,30][n];if(mult>=mst){pyrs[p.mint]=(n+1);const add=Math.min(p.size*[.5,.35,.2][n],paperBal*.25);if(add>=.5){paperBal-=add;const tot=p.size+add;p.entry=(p.size*p.entry+add*p.current)/tot;p.size=tot;log('buy',`PYRAMID #${n+1} ${p.token}`,`+$${add.toFixed(2)} at ${mult.toFixed(1)}x`);}}}
    let reason=null;
    if(pct<=-sl)reason=`Stop -${sl}%`;
    else if(trail>=ts&&pct>20)reason=`Trail -${ts}%`;
    else if(hrs>=C.MAX_HOLD)reason=`Time ${C.MAX_HOLD}h`;
    if(!reason&&pct>30){const ae=await aiExit(p,pct,trail,hrs,mult);if(ae.exit)reason=ae.reason;}
    if(reason)await doExit(i,p,pct,reason);
  }
}

// ── Main cycle ────────────────────────────────────────
async function runCycle(){
  if(!running)return;
  cycle++;
  log('info',`CYCLE #${cycle}`,`${C.MODE} · ${positions.length}pos · $${paperBal.toFixed(2)}`);
  try{
    await fetchPrice();
    const runners=await fetchRunners();
    updateRegime(runners);
    log('info','SCAN',`${runners.length} gems · ${regime}`);
    await checkExits();
    if(positions.length<C.MAX_POS&&runners.length){
      const todo=runners.filter(p=>{const m=p.baseToken?.address;return m&&!positions.some(x=>x.mint===m)&&!analyzing.has(m);}).slice(0,3);
      for(const p of todo){
        if(!running)break;
        const mint=p.baseToken?.address,sym=p.baseToken?.symbol||'?';
        analyzing.add(mint);
        try{
          let rsk=25;if(C.ANTIRUG)rsk=await risk(mint);
          if(rsk>C.MAX_RISK){log('skip',`ANTIRUG ${sym}`,`${rsk}/100`);continue;}
          const dec=await aiDecide(p,rsk);
          if(dec.action==='BUY')await doBuy(p,dec,rsk);
          else log('skip',`SKIP ${sym}`,dec.reasoning.slice(0,70));
        }catch(e){log('warn',`ERR ${sym}`,e.message.slice(0,70));}
        analyzing.delete(mint);
      }
    }
    await updatePrices();
  }catch(e){log('warn','CYCLE ERR',e.message.slice(0,70));}
  if(running)nextTimer=setTimeout(runCycle,C.INTERVAL*1000);
}

// ── Dashboard ─────────────────────────────────────────
function stats(){
  const total=paperBal+positions.reduce((s,p)=>s+p.size*((p.current||p.entry)/p.entry),0);
  const pnl=total-C.START_BAL,wins2=trades.filter(t=>t.pnl>0),losses2=trades.filter(t=>t.pnl<=0);
  const avgW=wins2.length?wins2.reduce((a,t)=>a+t.pnl,0)/wins2.length:0;
  const avgL=losses2.length?losses2.reduce((a,t)=>a+Math.abs(t.pnl),0)/losses2.length:0;
  const up=startedAt?Math.floor((Date.now()-startedAt)/1000):0;
  return{total:total.toFixed(2),pnl:pnl.toFixed(2),pnlPct:(pnl/C.START_BAL*100).toFixed(1),
    wr:trades.length?(wins2.length/trades.length*100).toFixed(1)+'%':'—',
    pf:avgL>0?(avgW/avgL).toFixed(2):'∞',avgW:avgW.toFixed(2),avgL:avgL.toFixed(2),
    wins,losses,total_trades:trades.length,
    best:trades.length?trades.reduce((a,b)=>b.pnl>a.pnl?b:a,{pnl:-999,token:'—',pct:0}):null,
    uptime:`${Math.floor(up/3600)}:${String(Math.floor((up%3600)/60)).padStart(2,'0')}:${String(up%60).padStart(2,'0')}`,
    solPrice:solPrice.toFixed(2),regime,mode:C.MODE,running,cycle,epoch:brain.epoch,btrades:brain.totalTrades};
}

function html(){
  const s=stats();
  const posR=positions.map((p,i)=>{const pct=p.entry?(p.current-p.entry)/p.entry*100:0;const m=p.current/p.entry;return`<tr><td>${p.token}</td><td>$${p.size.toFixed(1)}</td><td style="color:${pct>=0?'#00e87a':'#ff3355'}">${pct>=0?'+':''}${pct.toFixed(0)}%</td><td style="color:${m>=10?'#f5a623':'#8b5cf6'}">${m.toFixed(1)}x</td><td><a href="/exit/${i}" style="color:#ff3355">Exit</a></td></tr>`;}).join('');
  const tR=trades.slice(-10).reverse().map(t=>`<tr><td>${t.token}</td><td style="color:${t.pnl>=0?'#00e87a':'#ff3355'}">${t.pnl>=0?'+':''}$${t.pnl.toFixed(2)}</td><td>${t.pct.toFixed(0)}%</td></tr>`).join('');
  const lR=logs.slice(0,40).map(l=>{const c={buy:'#00e87a',sell:'#ff3355',skip:'#4a6080',info:'#3b9eff',warn:'#ffb020'}[l.type]||'#d4e5ff';return`<div style="padding:3px 0;border-bottom:1px solid #111;font-size:11px"><span style="color:#4a6080">${l.ts.slice(11,19)}</span> <span style="color:${c};font-weight:600">${l.label}</span> <span style="color:#4a6080">${(l.detail||'').slice(0,80)}</span></div>`;}).join('');
  const ins=brain.insights.length?`"${brain.insights[0].text.slice(0,200)}"`:'"Run the bot for a few trades to generate AI insights."';
  return`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>🌕 Gem Hunter</title><meta http-equiv="refresh" content="15"><style>*{box-sizing:border-box;margin:0;padding:0}body{background:#070a10;color:#d4e5ff;font-family:system-ui,sans-serif;font-size:13px;padding:12px}h2{font-size:12px;font-weight:700;color:#4a6080;text-transform:uppercase;letter-spacing:.08em;margin:14px 0 7px}.g2{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px}.card{background:#0d1117;border:1px solid #1a2332;border-radius:9px;padding:10px 12px}.lbl{font-size:10px;color:#4a6080;text-transform:uppercase;letter-spacing:.05em;margin-bottom:3px}.val{font-size:18px;font-weight:700;font-family:monospace}.g{color:#00e87a}.r{color:#ff3355}.p{color:#8b5cf6}.a{color:#ffb020}.b{color:#3b9eff}.status{display:flex;align-items:center;gap:8px;background:#0d1117;border:1px solid #1a2332;border-radius:8px;padding:10px 12px;margin-bottom:12px}.dot{width:8px;height:8px;border-radius:50%}.on{background:#00e87a;box-shadow:0 0 6px #00e87a;animation:pulse 1.5s infinite}.off{background:#4a6080}@keyframes pulse{50%{opacity:.3}}.btn-row{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}a.btn{display:inline-block;padding:9px 18px;border-radius:7px;font-weight:700;font-size:13px;text-decoration:none}.bg{background:#00e87a;color:#000}.br{background:#ff3355;color:#fff}.bx{background:#1a2332;color:#d4e5ff}table{width:100%;border-collapse:collapse;font-size:11px}th{text-align:left;padding:5px 6px;color:#4a6080;font-weight:600;border-bottom:1px solid #1a2332;font-size:10px;text-transform:uppercase}td{padding:6px;border-bottom:1px solid #0d1117}.tw{background:#0d1117;border:1px solid #1a2332;border-radius:8px;overflow:hidden;margin-bottom:12px}.log{background:#0d1117;border:1px solid #1a2332;border-radius:8px;padding:10px;height:220px;overflow-y:auto;font-family:monospace}.brain{display:flex;gap:12px;flex-wrap:wrap;background:#0d1117;border:1px solid #1a2332;border-radius:8px;padding:10px 12px;margin-bottom:12px}.bi{display:flex;flex-direction:column;gap:2px}.bl{font-size:9px;text-transform:uppercase;color:#4a6080}.bv{font-family:monospace;font-size:13px;font-weight:700}.ins{background:#0d1117;border:1px solid rgba(139,92,246,.25);border-radius:8px;padding:10px 12px;font-size:12px;line-height:1.6;margin-bottom:12px;font-style:italic;color:#c8c0ff}</style></head><body>
<div style="font-size:20px;font-weight:800;margin-bottom:12px;background:linear-gradient(90deg,#8b5cf6,#f5a623,#00e87a);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text">🌕 GEM HUNTER</div>
<div class="status"><span class="dot ${s.running?'on':'off'}"></span><b>${s.running?'RUNNING':'STOPPED'}</b><span style="color:#4a6080">· ${s.mode.toUpperCase()} · cycle #${s.cycle} · ${s.uptime}</span><span style="margin-left:auto;color:#4a6080">SOL $${s.solPrice} · ${s.regime}</span></div>
<div class="btn-row"><a href="/start" class="btn bg">▶ START</a><a href="/stop" class="btn br">■ STOP</a><a href="/" class="btn bx">↻ Refresh</a></div>
<div class="g2">
<div class="card"><div class="lbl">Portfolio</div><div class="val ${parseFloat(s.pnl)>=0?'g':'r'}">$${s.total}</div><div style="font-size:11px;color:#4a6080">${parseFloat(s.pnl)>=0?'+':''}${s.pnl} (${s.pnlPct}%)</div></div>
<div class="card"><div class="lbl">Win Rate</div><div class="val">${s.wr}</div><div style="font-size:11px;color:#4a6080">${s.wins}W / ${s.losses}L · ${s.total_trades} trades</div></div>
<div class="card"><div class="lbl">Profit Factor</div><div class="val ${parseFloat(s.pf)>=1.5?'g':parseFloat(s.pf)>=1?'a':'r'}">${s.pf}</div><div style="font-size:11px;color:#4a6080">$${s.avgW} win / $${s.avgL} loss</div></div>
<div class="card"><div class="lbl">Best Trade</div><div class="val g">${s.best&&s.best.pnl>-999?'+$'+s.best.pnl.toFixed(2):'—'}</div><div style="font-size:11px;color:#4a6080">${s.best&&s.best.pnl>-999?s.best.token+' +'+s.best.pct.toFixed(0)+'%':'—'}</div></div>
</div>
<div class="brain"><div class="bi"><div class="bl">Epoch</div><div class="bv p">${s.epoch}</div></div><div class="bi"><div class="bl">Brain</div><div class="bv">${s.btrades} trades</div></div><div class="bi"><div class="bl">Min BSR</div><div class="bv b">${brain.evolvedParams.minBSR.toFixed(2)}x</div></div><div class="bi"><div class="bl">Min Score</div><div class="bv b">${brain.evolvedParams.minScore}</div></div><div class="bi"><div class="bl">Kelly</div><div class="bv b">${(brain.evolvedParams.kellyFraction*100).toFixed(0)}%</div></div></div>
<div class="ins">🧠 ${ins}</div>
<h2>Open Positions (${positions.length}/${C.MAX_POS})</h2>
<div class="tw">${positions.length?`<table><thead><tr><th>Token</th><th>Size</th><th>P&L</th><th>Mult</th><th></th></tr></thead><tbody>${posR}</tbody></table>`:'<div style="padding:12px;color:#4a6080;text-align:center">No open positions</div>'}</div>
<h2>Recent Trades</h2>
<div class="tw">${trades.length?`<table><thead><tr><th>Token</th><th>P&L</th><th>Return</th></tr></thead><tbody>${tR}</tbody></table>`:'<div style="padding:12px;color:#4a6080;text-align:center">No trades yet</div>'}</div>
<h2>Live Log</h2><div class="log">${lR}</div>
<div style="color:#4a6080;font-size:10px;margin-top:10px;text-align:center">Auto-refreshes every 15s · <a href="/api/state" style="color:#3b9eff">JSON API</a></div>
</body></html>`;
}

const server=http.createServer(async(req,res)=>{
  const url=req.url.split('?')[0];
  if(url==='/start'){if(!running){running=true;startedAt=Date.now();log('info','START','via dashboard');runCycle();}res.writeHead(302,{Location:'/'});res.end();return;}
  if(url==='/stop'){running=false;clearTimeout(nextTimer);log('info','STOP','via dashboard');res.writeHead(302,{Location:'/'});res.end();return;}
  if(url.startsWith('/exit/')){const i=parseInt(url.split('/')[2]);if(positions[i]){const p=positions[i];const pct=p.entry?(p.current-p.entry)/p.entry*100:0;await doExit(i,p,pct,'Manual exit');}res.writeHead(302,{Location:'/'});res.end();return;}
  if(url==='/api/state'){res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({stats:stats(),positions,recentTrades:trades.slice(-20),brain:{epoch:brain.epoch,totalTrades:brain.totalTrades,evolvedParams:brain.evolvedParams,insights:brain.insights.slice(0,3)},logs:logs.slice(0,50)},null,2));return;}
  res.writeHead(200,{'Content-Type':'text/html'});res.end(html());
});

server.listen(C.PORT,()=>{
  console.log('\n╔══════════════════════════════════════════╗');
  console.log('║      🌕 GEM HUNTER BOT — STARTED        ║');
  console.log('╚══════════════════════════════════════════╝\n');
  console.log(`  Mode:      ${C.MODE.toUpperCase()}`);
  console.log(`  AI:        ${C.CLAUDE_KEY?'✅ Claude active':'⚠️  No key — rule-based'}`);
  console.log(`  Dashboard: http://localhost:${C.PORT}`);
  console.log(`  Data:      ${path.resolve(C.DATA)}`);
  console.log(`  Balance:   $${C.START_BAL} paper\n`);
  console.log('  Open dashboard to start: http://localhost:'+C.PORT+'\n');
  log('info','BOOT',`port=${C.PORT} mode=${C.MODE} ai=${!!C.CLAUDE_KEY}`);
});

process.on('SIGINT', ()=>{log('info','SHUTDOWN','SIGINT');process.exit(0);});
process.on('SIGTERM',()=>{log('info','SHUTDOWN','SIGTERM');process.exit(0);});
process.on('uncaughtException',e=>log('warn','UNCAUGHT',e.message));
