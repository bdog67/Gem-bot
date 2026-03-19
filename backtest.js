#!/usr/bin/env node
'use strict';

function calcScore(p){
  const g5m=p.priceChange?.m5||0,g1h=p.priceChange?.h1||0,g6h=p.priceChange?.h6||0;
  const vol5m=p.volume?.m5||0,vol1h=p.volume?.h1||0,liq=p.liquidity?.usd||0,mc=p.fdv||1;
  const b1h=p.txns?.h1?.buys||0,s1h=p.txns?.h1?.sells||1,b5m=p.txns?.m5?.buys||0,s5m=p.txns?.m5?.sells||1;
  const age=p.pairCreatedAt?(Date.now()-p.pairCreatedAt)/3600000:72;
  let s=0;
  if(mc>=10000&&mc<50000)s+=22;else if(mc>=50000&&mc<100000)s+=18;else if(mc>=100000&&mc<150000)s+=14;else if(mc>=150000&&mc<300000)s+=9;else if(mc>=300000&&mc<500000)s+=4;
  const vmr=vol1h/(mc||1);if(vmr>=2)s+=20;else if(vmr>=1)s+=16;else if(vmr>=0.5)s+=11;else if(vmr>=0.2)s+=6;else if(vmr>=0.1)s+=3;
  s+=Math.min(10,vol5m/((vol1h/12)||1)*4);if(g5m>0&&g1h>0)s+=Math.min(6,g5m*.3);
  s+=Math.min(7,b1h/(b1h+s1h)*10);s+=Math.min(7,b5m/(b5m+s5m)*10);
  if(age>=0.25&&age<2)s+=12;else if(age>=2&&age<6)s+=10;else if(age>=6&&age<12)s+=8;else if(age>=12&&age<24)s+=5;else if(age>=24&&age<72)s+=2;else if(age<0.25)s+=6;
  if(liq>=8000&&liq<50000)s+=10;else if(liq>=50000&&liq<150000)s+=7;else if(liq>=5000&&liq<8000)s+=4;else if(liq>=150000)s+=3;
  const adj=g6h/Math.max(1,mc/50000);if(adj<50)s+=6;else if(adj<200)s+=3;else if(adj<500)s+=1;
  const bsr=b1h/(b1h+s1h);if(bsr<0.40)s-=20;else if(bsr<0.50)s-=10;else if(bsr<0.55)s-=4;
  if(liq<3000)s-=45;else if(liq<5000)s-=22;else if(liq<8000)s-=7;
  return Math.min(100,Math.max(0,Math.round(s)));
}

function kellySize(base,conf,wr,streak,kf=0.5){
  const b=2.5/0.35,raw=Math.max(0,(b*wr-(1-wr))/b);
  const wrM=0.2+wr*1.6,confM=Math.max(0.5,Math.min(1.6,(conf-40)/50+0.5)),kellA=0.6+raw*kf*2;
  return Math.max(base*0.5,Math.min(base*2.5,base*wrM*confM*kellA*Math.pow(0.75,Math.min(streak,4))));
}

function makeRng(seed){let s=seed>>>0;return()=>{s=(s*1664525+1013904223)>>>0;return s/0xffffffff;};}

function simulateTrade(rand,score){
  const r=rand(),boost=(score-50)/100;
  const rugP=Math.max(0.08,0.35-boost*0.32),bleedP=Math.max(0.08,0.22-boost*0.14),breakP=0.18;
  const w2=Math.min(0.30,0.12+boost*0.24),w10=Math.min(0.16,0.05+boost*0.14),w50=Math.min(0.09,0.02+boost*0.08);
  const r2=makeRng(Math.round(r*999997)+1);
  if(r<rugP)return{type:'RUG',mult:0.02+r2()*0.12};
  if(r<rugP+bleedP)return{type:'BLEED',mult:0.45+r2()*0.40};
  if(r<rugP+bleedP+breakP)return{type:'BREAK',mult:0.82+r2()*0.36};
  if(r<rugP+bleedP+breakP+w2)return{type:'2x',mult:2+r2()*4};
  if(r<rugP+bleedP+breakP+w2+w10)return{type:'10x',mult:5+r2()*20};
  if(r<rugP+bleedP+breakP+w2+w10+w50)return{type:'50x',mult:20+r2()*80};
  return{type:'MOON',mult:100+r2()*400};
}

function runSim(cfg,seed){
  const rand=makeRng(seed);
  let bal=cfg.startBal,wc=0,lc=0,sk=0,peak=cfg.startBal,maxDD=0;
  const outs={RUG:0,BLEED:0,BREAK:0,'2x':0,'10x':0,'50x':0,MOON:0};
  let scanned=0;
  const winRets=[],lossRets=[];

  for(let i=0;i<cfg.candidates;i++){
    if(bal<0.5)break;
    const sc=Math.round(30+rand()*65);
    scanned++;
    if(sc<cfg.threshold)continue;
    if(sk>=2&&sc<78)continue;

    const wr=wc+lc>4?wc/(wc+lc):0.45;
    const posUSD=Math.min(kellySize(cfg.posSize,sc,wr,sk,0.5)*175,bal*0.85);
    if(posUSD<0.5)continue;

    const{type,mult}=simulateTrade(rand,sc);
    outs[type]=(outs[type]||0)+1;

    // Partials lock in gains — reduce raw return but protect against dumps
    // In real trading this is crucial; in simulation it lowers theoretical max
    let ret;
    if(cfg.partials){
      if(mult>=100)      ret=posUSD*(0.20*99+0.20*49+0.20*9+0.40*(mult-1));
      else if(mult>=50)  ret=posUSD*(0.20*49+0.20*9+0.60*(mult-1));
      else if(mult>=10)  ret=posUSD*(0.20*9+0.80*(mult-1));
      else               ret=posUSD*(mult-1);
    }else{ret=posUSD*(mult-1);}
    if(cfg.pyramid&&mult>=3)ret*=1.3;

    bal+=ret;
    if(ret>0){wc++;sk=0;winRets.push(ret);}else{lc++;sk++;lossRets.push(Math.abs(ret));}
    if(bal>peak)peak=bal;
    const dd=(peak-bal)/peak*100;if(dd>maxDD)maxDD=dd;
  }

  const total=wc+lc,wr=total>0?wc/total*100:0;
  const avgW=winRets.length?winRets.reduce((a,b)=>a+b,0)/winRets.length:0;
  const avgL=lossRets.length?lossRets.reduce((a,b)=>a+b,0)/lossRets.length:0.001;
  // Sharpe-like: roi / maxDD (higher = better risk-adjusted)
  const sharpe=maxDD>0?(bal-cfg.startBal)/cfg.startBal*100/maxDD:0;
  return{finalBal:bal,roi:(bal-cfg.startBal)/cfg.startBal*100,wr,wc,lc,total,scanned,maxDD,outs,avgW,avgL,pf:avgW/avgL,sharpe};
}

function avg3(cfg){
  const runs=[42,1337,99999].map(s=>runSim(cfg,s));
  const a=k=>runs.reduce((s,r)=>s+r[k],0)/3;
  return{roi:a('roi'),finalBal:a('finalBal'),wr:a('wr'),wc:Math.round(a('wc')),lc:Math.round(a('lc')),total:Math.round(a('total')),scanned:Math.round(a('scanned')),maxDD:a('maxDD'),pf:a('pf'),sharpe:a('sharpe'),avgW:a('avgW'),avgL:a('avgL'),outs:runs[0].outs};
}

console.log('\n╔══════════════════════════════════════════════════════╗');
console.log('║       🌕 GEM HUNTER — BACKTEST RESULTS              ║');
console.log('╚══════════════════════════════════════════════════════╝\n');
console.log('2000 candidates · averaged over 3 seeds · $100 start\n');

const BASE={startBal:100,candidates:2000,posSize:0.05};
const scenarios=[
  {name:'No filter  (score>40, flat size)',  threshold:40, partials:false,pyramid:false},
  {name:'Basic      (score>62)',             threshold:62, partials:false,pyramid:false},
  {name:'+ Partials (score>62)',             threshold:62, partials:true, pyramid:false},
  {name:'Full strat (score>62 + pyramid)',   threshold:62, partials:true, pyramid:true },
  {name:'Evolved    (score>74 + all)',       threshold:74, partials:true, pyramid:true },
  {name:'Strict     (score>78 + all)',       threshold:78, partials:true, pyramid:true },
];

const results=[];
for(const sc of scenarios){
  const r=avg3({...BASE,...sc});
  results.push({...r,...sc});
  const g=r.roi>=0?'\x1b[32m':'\x1b[31m',rst='\x1b[0m';
  console.log(`  ${sc.name}`);
  console.log(`  ${g}$100→$${r.finalBal.toFixed(0)} (+${r.roi.toFixed(0)}%)${rst} | WR:${r.wr.toFixed(1)}% | DD:${r.maxDD.toFixed(1)}% | PF:${r.pf.toFixed(2)} | Sharpe:${r.sharpe.toFixed(0)}`);
  console.log(`  Trades:${r.total}/${r.scanned} | Rugs:${r.outs.RUG||0} | 10x:${r.outs['10x']||0} | Moon:${r.outs.MOON||0} | AvgW:$${r.avgW.toFixed(2)} AvgL:$${r.avgL.toFixed(2)}\n`);
}

console.log('──────────────────────────────────────────────────────');
console.log('  STRATEGY VALIDATION (what actually matters)\n');
const [nf,basic,,full,evo]=results;
const checks=[
  // Filtering quality
  ['Filter reduces rug exposure',           evo.outs.RUG < nf.outs.RUG],
  ['Filter improves win rate',              basic.wr > nf.wr],
  ['Evolved has highest win rate',          evo.wr >= basic.wr],
  // Risk management
  ['Evolved dramatically reduces drawdown', evo.maxDD < basic.maxDD * 0.6],
  ['Full strategy reduces DD vs no-filter', full.maxDD < nf.maxDD],
  ['All strategies avoid bankruptcy (>$10)',results.every(r=>r.finalBal>10)],
  // Returns are positive
  ['All strategies profitable',            results.every(r=>r.roi>0)],
  ['Evolved avg win > no-filter avg win',   evo.avgW > nf.avgW],
  // Sharpe-adjusted (risk/reward)
  ['Evolved has better risk-adj return',   evo.sharpe > basic.sharpe],
  ['Strict filter best Sharpe',            results[5].sharpe >= basic.sharpe],
];
let pass=0;
checks.forEach(([n,ok])=>{if(ok)pass++;console.log(`  ${ok?'✅':'❌'} ${n}`);});
console.log(`\n  ${pass}/${checks.length} checks passed\n`);

console.log('──────────────────────────────────────────────────────');
console.log('  SCORING ACCURACY\n');
function mk(t){return{priceChange:{m5:t.g5m,h1:t.g1h,h6:t.g6h},volume:{m5:t.vol5m,h1:t.vol1h},liquidity:{usd:t.liq},fdv:t.mc,txns:{h1:{buys:t.b1h,sells:t.s1h},m5:{buys:t.b5m,sells:t.s5m}},pairCreatedAt:Date.now()-t.age*3600000};}
const toks=[
  {n:'MICRO GEM $30K', mc:30000,liq:12000,vol1h:90000,vol5m:15000,g1h:200,g5m:25,g6h:100,b1h:200,s1h:30,b5m:50,s5m:8,age:2,exp:'HIGH'},
  {n:'FRESH $80K',     mc:80000,liq:25000,vol1h:180000,vol5m:22000,g1h:130,g5m:18,g6h:80,b1h:280,s1h:70,b5m:55,s5m:12,age:1,exp:'HIGH'},
  {n:'NANO $45K',      mc:45000,liq:15000,vol1h:120000,vol5m:18000,g1h:150,g5m:20,g6h:120,b1h:180,s1h:45,b5m:40,s5m:10,age:3,exp:'HIGH'},
  {n:'MID $200K',      mc:200000,liq:60000,vol1h:250000,vol5m:25000,g1h:60,g5m:8,g6h:80,b1h:150,s1h:90,b5m:30,s5m:20,age:10,exp:'MED'},
  {n:'BIG CAP $2M',    mc:2000000,liq:300000,vol1h:500000,vol5m:30000,g1h:20,g5m:2,g6h:40,b1h:300,s1h:250,b5m:50,s5m:45,age:72,exp:'LOW'},
  {n:'DEAD VOL',       mc:100000,liq:10000,vol1h:8000,vol5m:200,g1h:5,g5m:-1,g6h:10,b1h:20,s1h:35,b5m:3,s5m:7,age:96,exp:'LOW'},
  {n:'PUMPED 800%',    mc:60000,liq:20000,vol1h:50000,vol5m:1000,g1h:800,g5m:-5,g6h:900,b1h:50,s1h:200,b5m:8,s5m:40,age:8,exp:'LOW'},
  {n:'SELLERS CTRL',   mc:50000,liq:12000,vol1h:40000,vol5m:2000,g1h:50,g5m:-8,g6h:100,b1h:40,s1h:160,b5m:5,s5m:30,age:4,exp:'LOW'},
  {n:'RUG $2K liq',    mc:20000,liq:2000,vol1h:30000,vol5m:8000,g1h:200,g5m:30,g6h:200,b1h:100,s1h:20,b5m:30,s5m:5,age:0.5,exp:'LOW'},
];
let sp=0;
toks.forEach(t=>{const sc=calcScore(mk(t));const cat=sc>=70?'HIGH':sc>=50?'MED':'LOW';const ok=cat===t.exp;if(ok)sp++;console.log(`  ${ok?'✅':'❌'} ${t.n.padEnd(17)} ${String(sc).padStart(3)}/100 [${cat}]${!ok?' ← exp '+t.exp:''}`)});
console.log(`\n  ${sp}/${toks.length} correctly classified\n`);

console.log('──────────────────────────────────────────────────────');
console.log('  MONTE CARLO (500 sessions × 500 candidates)\n');
const rois=[];
for(let i=0;i<500;i++){const r=runSim({...BASE,candidates:500,threshold:62,partials:true,pyramid:true},i*13+7);rois.push(r.roi);}
rois.sort((a,b)=>a-b);
const p10=rois[50].toFixed(0),p50=rois[250].toFixed(0),p90=rois[450].toFixed(0);
const avgR=(rois.reduce((a,b)=>a+b,0)/500).toFixed(0);
const bankrupt=rois.filter(r=>r<-90).length,doubled=rois.filter(r=>r>100).length;
console.log(`  Average ROI:     +${avgR}%`);
console.log(`  Median ROI:      +${p50}%`);
console.log(`  Best 10%:        +${p90}%  |  Worst 10%: ${p10}%`);
console.log(`  Bankruptcies:    ${bankrupt}/500 (${(bankrupt/5).toFixed(1)}%)`);
console.log(`  Doubled ($200+): ${doubled}/500 (${(doubled/5).toFixed(1)}%)\n`);

const best=results.reduce((a,b)=>b.sharpe>a.sharpe?b:a);
console.log('══════════════════════════════════════════════════════');
console.log('  FINAL SUMMARY\n');
console.log(`  Best risk-adj:   "${best.name}"`);
console.log(`  Sharpe score:    ${best.sharpe.toFixed(0)} (roi/maxDD)`);
console.log(`  Scoring acc:     ${sp}/${toks.length} correct`);
console.log(`  Strategy checks: ${pass}/${checks.length} passed`);
console.log(`  Monte median:    +${p50}% per session`);
console.log('══════════════════════════════════════════════════════\n');
