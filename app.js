/* ═══════════════════════════════════════════════════════════
   ميزانية البيت — v25 (نسخة تجارية)
   الترخيص: Firebase Auth + Firestore (بريد + تاريخ انتهاء + أجهزة فقط)
   البيانات المالية: محلية 100% ومشفّرة AES-GCM — لا تُرسل لأي خادم
   © سُحُب · LSY — جميع الحقوق محفوظة
   ES5 فقط (توافق iOS Safari)
   ═══════════════════════════════════════════════════════════ */
(function(){
"use strict";

var APP_VERSION = "25.4";
var CURRENCIES = [
  {code:"BHD", lbl:"د.ب", dec:3},{code:"KWD", lbl:"د.ك", dec:3},{code:"OMR", lbl:"ر.ع", dec:3},
  {code:"SAR", lbl:"ر.س", dec:2},{code:"AED", lbl:"د.إ", dec:2},{code:"QAR", lbl:"ر.ق", dec:2},
  {code:"EGP", lbl:"ج.م", dec:2},{code:"USD", lbl:"$",   dec:2}
];
var CUR = "د.ب";
var DATA_VERSION = 3;
/* licenseMode "off" = local-only (no login/licence); "firebase" = full commercial mode */
var LOCAL_MODE = typeof APP_SETTINGS==="undefined"||APP_SETTINGS.licenseMode!=="firebase";
var LOCAL_NS = "mb2_local_";
var MN  = ["يناير","فبراير","مارس","أبريل","مايو","يونيو","يوليو","أغسطس","سبتمبر","أكتوبر","نوفمبر","ديسمبر"];
var PIN_LEN = 6;
var AUTOLOCK_MS = 60000;
var BACKUP_DAYS = 14;
var KDF_ITER = 150000;

var SEC_QUESTIONS = [
  "ما اسم مدرستك الابتدائية؟",
  "ما اسم أول صديق لك؟",
  "في أي مدينة وُلدت والدتك؟",
  "ما اسم الحي الذي نشأت فيه؟"
];

var DEFAULT_EXP_CATS = [
  {id:"groceries",   lbl:"بقالة",    em:"🛒", c:"#0EA370"},
  {id:"food",        lbl:"طعام",     em:"🍽️", c:"#F97316"},
  {id:"debt",        lbl:"ديون",     em:"💳", c:"#E5484D"},
  {id:"children",    lbl:"أطفال",    em:"👶", c:"#EC4899"},
  {id:"car",         lbl:"سيارة",    em:"🚗", c:"#6366F1"},
  {id:"fuel",        lbl:"وقود",     em:"⛽", c:"#8B5CF6"},
  {id:"health",      lbl:"صحة",      em:"🏥", c:"#14B8A6"},
  {id:"home",        lbl:"بيت",      em:"🏠", c:"#3B82F6"},
  {id:"electricity", lbl:"كهرباء",   em:"💡", c:"#EAB308"},
  {id:"mobile",      lbl:"موبايل",   em:"📱", c:"#06B6D4"},
  {id:"shopping",    lbl:"مشتريات",  em:"🛍️", c:"#A855F7"},
  {id:"entertain",   lbl:"ترفيه",    em:"🎮", c:"#F43F5E"},
  {id:"travel",      lbl:"سفر",      em:"✈️", c:"#0EA5E9"},
  {id:"other",       lbl:"أخرى",     em:"📦", c:"#9CA3AF"}
];
var DEFAULT_INC_CATS = [
  {id:"salary",  lbl:"الراتب",     em:"💰", c:"#0EA370"},
  {id:"income2", lbl:"دخل ثانوي", em:"💼", c:"#3B82F6"},
  {id:"shop",    lbl:"المتجر",    em:"🏪", c:"#D97706"},
  {id:"other",   lbl:"أخرى",      em:"📥", c:"#8B5CF6"}
];
var COMMIT_EMOJIS = ["🏠","🚗","📱","💡","🌊","🎓","🏦","🛡️","📺","💊","🧹","🔧","💳","📋","🏋️","☕"];
var ACCENTS = ["#1D6FA4","#0E7490","#0EA370","#4F46E5","#7C3AED","#C2185B","#E5484D","#D97706","#374151"];
var CAT_COLORS=["#0EA370","#F97316","#E5484D","#EC4899","#6366F1","#8B5CF6","#14B8A6","#3B82F6","#EAB308","#06B6D4","#A855F7","#F43F5E","#0EA5E9","#D97706","#84CC16","#64748B","#78716C","#9CA3AF"];
var CAT_EMOJIS=["🛒","🍽️","💳","👶","🚗","⛽","🏥","🏠","💡","📱","🛍️","🎮","✈️","💰","💼","🏪","📥","📦","🧹","🔧","🎓","🏋️","💊","🎁","📚","☕","🎵","🍕","🧴","🐾","💈","🌿"];

/* ═══════════════ STORAGE (raw) ═══════════════ */
function ld(k,d){try{var s=localStorage.getItem(k);return s?JSON.parse(s):d;}catch(e){return d;}}
function sv(k,v){try{localStorage.setItem(k,JSON.stringify(v));return true;}catch(e){return false;}}
function rm(k){try{localStorage.removeItem(k);}catch(e){}}

/* ═══════════════ CRYPTO ═══════════════ */
var subtle = (window.crypto && window.crypto.subtle) ? window.crypto.subtle : null;
var enc = new TextEncoder(), dec = new TextDecoder();

function b64(buf){var b=new Uint8Array(buf),s="";for(var i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);return btoa(s);}
function unb64(str){var s=atob(str),b=new Uint8Array(s.length);for(var i=0;i<s.length;i++)b[i]=s.charCodeAt(i);return b;}
function rnd(n){var b=new Uint8Array(n);window.crypto.getRandomValues(b);return b;}
function sha256Hex(str){
  return subtle.digest("SHA-256",enc.encode(str)).then(function(h){
    var b=new Uint8Array(h),s="";for(var i=0;i<b.length;i++)s+=("0"+b[i].toString(16)).slice(-2);return s;
  });
}
function kdf(secret,salt){
  return subtle.importKey("raw",enc.encode(secret),{name:"PBKDF2"},false,["deriveKey"]).then(function(base){
    return subtle.deriveKey({name:"PBKDF2",salt:salt,iterations:KDF_ITER,hash:"SHA-256"},base,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
  });
}
function importDataKey(raw){return subtle.importKey("raw",raw,{name:"AES-GCM"},false,["encrypt","decrypt"]);}
function aesEnc(key,bytes){var iv=rnd(12);return subtle.encrypt({name:"AES-GCM",iv:iv},key,bytes).then(function(ct){return {iv:b64(iv),ct:b64(ct)};});}
function aesDec(key,blob){return subtle.decrypt({name:"AES-GCM",iv:unb64(blob.iv)},key,unb64(blob.ct)).then(function(pt){return new Uint8Array(pt);});}
/* wrap the raw data key with a secret (PIN / security answer / backup password) */
function wrapWith(secret,bytes){
  var salt=rnd(16);
  return kdf(secret,salt).then(function(k){return aesEnc(k,bytes);}).then(function(r){r.salt=b64(salt);return r;});
}
function unwrapWith(secret,w){
  return kdf(secret,unb64(w.salt)).then(function(k){return aesDec(k,w);});
}
function normAns(s){
  return String(s||"").toLowerCase().replace(/[ً-ْـ]/g,"").replace(/[أإآ]/g,"ا").replace(/ة/g,"ه").replace(/ى/g,"ي").replace(/\s+/g,"");
}

/* ═══════════════ STATE ═══════════════ */
var EXP_CATS = DEFAULT_EXP_CATS.slice();
var INC_CATS = DEFAULT_INC_CATS.slice();
var S = null;           // decrypted state (memory only)
var NS = "";            // per-user storage namespace
var RAW = null;         // raw data key (memory only, while unlocked)
var DKEY = null;        // CryptoKey for data
var VAULT = null;       // vault metadata
var USER = null;        // firebase user
var LIC = null;         // license info
var hiddenAt = 0;
var pinFails = 0, pinLockUntil = 0;

function freshState(){
  return {txs:[],onboarded:false,accent:"#1D6FA4",expCats:DEFAULT_EXP_CATS.slice(),incCats:DEFAULT_INC_CATS.slice(),commits:[],pinTipOff:false,lastBackup:0,createdAt:Date.now()};
}
/* category budget field was "budget" in older versions, "cap" now */
function normCats(arr){
  if(!arr||!arr.length)return arr;
  for(var i=0;i<arr.length;i++){var c=arr[i];if(c&&c.budget>0&&!(c.cap>0))c.cap=c.budget;if(c)delete c.budget;}
  return arr;
}
function legacyState(){
  var tx=ld("mb_tx",null); if(!tx) return null;
  var st=freshState();
  st.txs=tx; st.onboarded=true;
  st.expCats=normCats(ld("mb_ec",null))||st.expCats; st.incCats=ld("mb_ic",null)||st.incCats;
  st.commits=ld("mb_co",[])||[];
  var th=ld("mb_th",null);
  if(typeof th==="string"&&/^#[0-9a-fA-F]{6}$/.test(th)) st.accent=th; else if(th==="pink") st.accent="#C2185B";
  var cur=ld("mb_cur",null); if(cur&&cur.code) st.currency=cur;
  var lb=ld("mb_lb",null); if(lb) st.lastBackup=typeof lb==="number"?lb:(Date.parse(lb)||0);
  st.legacyPin=!!ld("mb_pe",false);
  return st;
}
function clearLegacy(){var k=["mb_tx","mb_on","mb_th","mb_ec","mb_ic","mb_co","mb_cur","mb_lb","mb_bs","mb_pe","mb_ph","mb_pq","mb_pa"];for(var i=0;i<k.length;i++)rm(k[i]);}
/* forward-only data upgrades — every future format change goes here */
function migrate(st){
  if(!st.v||st.v<3){ normCats(st.expCats); if(!st.currency||!st.currency.code) st.currency=CURRENCIES[0]; }
  if(!st.debts) st.debts=[];
  st.v=DATA_VERSION;
  return st;
}
function bindCats(){
  migrate(S);
  CUR=S.currency.lbl;
  if(!S.expCats||!S.expCats.length) S.expCats=DEFAULT_EXP_CATS.slice();
  if(!S.incCats||!S.incCats.length) S.incCats=DEFAULT_INC_CATS.slice();
  EXP_CATS=S.expCats; INC_CATS=S.incCats;
}

/* encrypted save — serialized so writes never overlap */
var saving=false, dirty=false;
function save(){ if(!DKEY||!S) return; dirty=true; if(!saving) flush(); }
function flush(){
  saving=true; dirty=false;
  S.expCats=EXP_CATS; S.incCats=INC_CATS;
  var key=DKEY, ns=NS;
  aesEnc(key,enc.encode(JSON.stringify(S))).then(function(blob){
    if(!sv(ns+"data",blob)) toast("⚠️ تعذّر الحفظ — مساحة التخزين ممتلئة");
    saving=false; if(dirty&&DKEY) flush();
  },function(){saving=false;toast("⚠️ خطأ في الحفظ");});
}

/* ═══════════════ UI STATE ═══════════════ */
var UI = {view:"home",tab:"home",month:new Date().toISOString().slice(0,7),obStep:0,editTx:null,editCat:null,editCatType:"expense",editCommit:null,pivotData:null,modalCb:null,selectedCat:null};

/* ═══════════════ HELPERS ═══════════════ */
function uid(){return "_"+Date.now()+"_"+Math.random().toString(36).slice(2,7);}
function curDec(){return (S&&S.currency&&S.currency.dec!=null)?S.currency.dec:3;}
function fmt(n){return Number(n||0).toFixed(curDec()).replace(/\B(?=(\d{3})+(?!\d))/g,",");}
function pad2(n){return (n<10?"0":"")+n;}
function today(){var d=new Date();return d.getFullYear()+"-"+pad2(d.getMonth()+1)+"-"+pad2(d.getDate());}
/* salary cycle: financial month starts on S.cycleDay (1 = calendar month) */
function cycDay(){return (S&&S.cycleDay>1)?S.cycleDay:1;}
function periodOf(ds){
  var cd=cycDay();if(cd===1)return ds.slice(0,7);
  var y=parseInt(ds.slice(0,4),10),m=parseInt(ds.slice(5,7),10),d=parseInt(ds.slice(8,10),10);
  if(d<cd){m--;if(m<1){m=12;y--;}}
  return y+"-"+pad2(m);
}
function thisMonth(){return periodOf(today());}
function monthLbl(ym){var p=ym.split("-");return MN[parseInt(p[1],10)-1]+" "+p[0];}
function periodRange(ym){
  var cd=cycDay();if(cd===1)return "";
  var m=parseInt(ym.split("-")[1],10),nm=m===12?1:m+1;
  return cd+" "+MN[m-1]+" – "+(cd-1)+" "+MN[nm-1];
}
function dateLbl(ms){var d=new Date(ms);return d.getDate()+" "+MN[d.getMonth()]+" "+d.getFullYear();}
function daysLeft(ms){return Math.ceil((ms-Date.now())/864e5);}
function daysW(n){return n===1?"يوم واحد":n===2?"يومين":(n>=3&&n<=10)?n+" أيام":n+" يوم";}
function getCat(type,id){
  var arr=type==="income"?INC_CATS:EXP_CATS;
  for(var i=0;i<arr.length;i++){if(arr[i].id===id)return arr[i];}
  return {id:"other",lbl:"أخرى",em:"📦",c:"#9CA3AF"};
}
function dataMonths(){
  var m={};m[thisMonth()]=1;
  for(var i=0;i<S.txs.length;i++) m[periodOf(S.txs[i].date)]=1;
  m[UI.month]=1;
  return Object.keys(m).sort().reverse();
}
function monthStats(ym){
  var inc=0,exp=0,commitExp=0,byEC={},byIC={},txs=[];
  for(var i=0;i<S.txs.length;i++){
    var t=S.txs[i]; if(periodOf(t.date)!==ym) continue;
    txs.push(t);
    if(t.type==="income"){inc+=t.amount;byIC[t.catId]=(byIC[t.catId]||0)+t.amount;}
    else{exp+=t.amount;byEC[t.catId]=(byEC[t.catId]||0)+t.amount;if(t.isCommit)commitExp+=t.amount;}
  }
  return {inc:inc,exp:exp,commitExp:commitExp,freeExp:exp-commitExp,bal:inc-exp,available:inc-commitExp,txs:txs,byEC:byEC,byIC:byIC};
}
function pendingCommits(){
  var m=thisMonth(),r=[];
  for(var i=0;i<S.commits.length;i++){var c=S.commits[i];if(!(c.appliedMonths&&c.appliedMonths.indexOf(m)>=0))r.push(c);}
  return r;
}
function totalCommits(){var t=0;for(var i=0;i<S.commits.length;i++)t+=S.commits[i].amount;return t;}
function darken(hex,f){
  var h=hex.replace("#","");if(h.length!==6)return hex;
  var r=Math.round(parseInt(h.substr(0,2),16)*f),g=Math.round(parseInt(h.substr(2,2),16)*f),b=Math.round(parseInt(h.substr(4,2),16)*f);
  return "#"+pad2h(r)+pad2h(g)+pad2h(b);
}
function pad2h(n){var s=n.toString(16);return s.length<2?"0"+s:s;}
function applyAccent(c){
  c=c||(S&&S.accent)||"#1D6FA4";
  var r=document.documentElement.style;
  r.setProperty("--theme-accent",c);r.setProperty("--theme-hdr1",c);r.setProperty("--theme-hdr2",darken(c,0.75));
  r.setProperty("--accent",c);r.setProperty("--accent-bg",c+"1A");
  var m=document.getElementById("meta-theme");if(m)m.setAttribute("content",c);
}
/* theme: stored in plain storage (not sensitive) so lock/login screens match too */
function themePref(){return ld("mb2_theme","auto");}
function applyTheme(){
  var t=themePref(),dark=t==="dark"||(t==="auto"&&window.matchMedia&&window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.setAttribute("data-theme",dark?"dark":"light");
}
if(window.matchMedia){
  var mq=window.matchMedia("(prefers-color-scheme: dark)");
  var onMq=function(){if(themePref()==="auto")applyTheme();};
  if(mq.addEventListener)mq.addEventListener("change",onMq);else if(mq.addListener)mq.addListener(onMq);
}
function openWA(msg){
  var a=document.createElement("a");
  a.href="https://wa.me/"+APP_SETTINGS.whatsapp+"?text="+encodeURIComponent(msg);
  a.target="_blank";a.rel="noopener noreferrer";document.body.appendChild(a);a.click();a.parentNode.removeChild(a);
}
function deviceId(){
  var id=ld("mb2_dev",null);
  if(!id){var b=rnd(9),s="d";for(var i=0;i<b.length;i++)s+=("0"+b[i].toString(16)).slice(-2);id=s;sv("mb2_dev",id);}
  return id;
}
function deviceName(){
  var u=navigator.userAgent||"";
  var n=/iPad/.test(u)?"iPad":/iPhone/.test(u)?"iPhone":/Android/.test(u)?"Android":/Macintosh/.test(u)?"Mac":/Windows/.test(u)?"Windows":"جهاز";
  return n+" · "+today();
}
function withTimeout(p,ms){
  return new Promise(function(res,rej){
    var t=setTimeout(function(){rej({code:"timeout"});},ms);
    p.then(function(v){clearTimeout(t);res(v);},function(e){clearTimeout(t);rej(e);});
  });
}

/* ═══════════════ DOM ═══════════════ */
function el(tag,props,kids){
  var e=document.createElement(tag);
  if(props){
    var keys=Object.keys(props);
    for(var i=0;i<keys.length;i++){
      var k=keys[i],v=props[k];
      if(v==null)continue;
      if(k==="cls") e.className=v;
      else if(k==="sty"){var sk=Object.keys(v);for(var j=0;j<sk.length;j++)e.style[sk[j]]=v[sk[j]];}
      else if(k.slice(0,2)==="on"&&typeof v==="function") e.addEventListener(k.slice(2),v);
      else e.setAttribute(k,v);
    }
  }
  if(kids!=null){
    var arr=Array.isArray(kids)?kids:[kids];
    for(var n=0;n<arr.length;n++){
      var c=arr[n]; if(c==null||c===false)continue;
      e.appendChild(typeof c==="string"||typeof c==="number"?document.createTextNode(String(c)):c);
    }
  }
  return e;
}
function mount(node){
  var root=document.getElementById("root");root.innerHTML="";root.appendChild(node);window.scrollTo(0,0);
  if(UI.focusEl){var f=UI.focusEl;UI.focusEl=null;try{f.focus();}catch(e){}}
}
function go(v){UI.view=v;render();}
function secTitle(t){return el("div",{cls:"sec-title"},t);}
function inpEl(attrs){var sty=attrs.sty;delete attrs.sty;attrs.cls=attrs.cls||"inp";var i=el("input",attrs);if(sty){var k=Object.keys(sty);for(var j=0;j<k.length;j++)i.style[k[j]]=sty[k[j]];}return i;}
function backBtn(to){return el("button",{cls:"back-btn",onclick:function(){go(to);}},"→");}
function hdrBar(title,to){
  var h=el("div",{cls:"hdr"});
  h.appendChild(el("div",{sty:{display:"flex",alignItems:"center"}},[backBtn(to),el("div",{sty:{fontSize:"19px",fontWeight:"900",color:"#fff"}},title)]));
  return h;
}

/* ═══════════════ TOAST / MODAL / ASK ═══════════════ */
var _tt;
function toast(msg){var t=document.getElementById("toast");t.textContent=msg;t.classList.add("show");clearTimeout(_tt);_tt=setTimeout(function(){t.classList.remove("show");},2600);}
function modal(title,body,warn,cb,okLbl){
  document.getElementById("modal-title").textContent=title;
  document.getElementById("modal-body").textContent=body||"";
  document.getElementById("modal-warn").style.display=warn?"block":"none";
  document.getElementById("modal-confirm").textContent=okLbl||"حذف";
  document.getElementById("modal-overlay").classList.add("show");
  UI.modalCb=cb;
}
function closeModal(){document.getElementById("modal-overlay").classList.remove("show");UI.modalCb=null;}
document.getElementById("modal-confirm").addEventListener("click",function(){var cb=UI.modalCb;closeModal();if(cb)cb();});
document.getElementById("modal-cancel").addEventListener("click",closeModal);
document.getElementById("modal-overlay").addEventListener("click",function(e){if(e.target.id==="modal-overlay")closeModal();});

/* generic input sheet: o={title,sub,fields:[{type,placeholder,value}],okLbl,onOk(values,close,setErr)} */
function askSheet(o){
  var ov=document.getElementById("ask-overlay"),sh=document.getElementById("ask-sheet");
  sh.innerHTML="";
  sh.appendChild(el("div",{cls:"sheet-handle"}));
  sh.appendChild(el("div",{cls:"sheet-title"},o.title));
  if(o.sub) sh.appendChild(el("div",{cls:"sheet-sub"},o.sub));
  var inputs=[];
  for(var i=0;i<o.fields.length;i++){
    var f=o.fields[i],inp;
    if(f.type==="select"){
      inp=el("select",{cls:"inp"});
      for(var j=0;j<f.options.length;j++){var op=el("option",{value:String(j)},f.options[j]);inp.appendChild(op);}
      if(f.value!=null) inp.value=f.value;
    } else inp=inpEl({type:f.type||"text",placeholder:f.placeholder||"",value:f.value||"",autocomplete:"off"});
    inputs.push(inp);sh.appendChild(inp);
  }
  var err=el("div",{cls:"gate-err"});sh.appendChild(err);
  var okB=el("button",{cls:"btn btn-accent"},o.okLbl||"متابعة");
  var cancel=el("button",{cls:"btn btn-ghost",onclick:close},"إلغاء");
  sh.appendChild(el("div",{cls:"btn-row"},[okB,cancel]));
  function close(){ov.classList.remove("show");sh.innerHTML="";}
  okB.addEventListener("click",function(){
    var vals=[];for(var i=0;i<inputs.length;i++)vals.push(inputs[i].value);
    err.textContent="";okB.disabled=true;
    o.onOk(vals,close,function(m){err.textContent=m;okB.disabled=false;});
  });
  ov.onclick=function(e){if(e.target===ov)close();};
  ov.classList.add("show");
  if(inputs[0]&&inputs[0].focus&&o.fields[0].type!=="select") setTimeout(function(){inputs[0].focus();},50);
}
function infoSheet(title,body){
  var ov=document.getElementById("ask-overlay"),sh=document.getElementById("ask-sheet");
  sh.innerHTML="";
  sh.appendChild(el("div",{cls:"sheet-handle"}));
  sh.appendChild(el("div",{cls:"sheet-title"},title));
  sh.appendChild(el("div",{cls:"sheet-sub"},body));
  sh.appendChild(el("button",{cls:"btn btn-accent",onclick:function(){ov.classList.remove("show");}},"تم"));
  ov.onclick=function(e){if(e.target===ov)ov.classList.remove("show");};
  ov.classList.add("show");
}

/* ═══════════════ GATE SCREENS ═══════════════ */
function gateWrap(kids){
  var g=el("div",{cls:"gate"},kids);
  g.appendChild(el("div",{cls:"brand-foot"},"\u200F© سُحُب · LSY  —  v"+APP_VERSION));
  return g;
}
function screenLoading(msg){
  mount(gateWrap([el("div",{cls:"spinner"}),el("div",{cls:"ob-body"},msg||"جاري التحميل…")]));
}
function screenSetupNeeded(){
  mount(gateWrap([el("div",{cls:"ob-emoji"},"🛠️"),el("div",{cls:"ob-title"},"الإعداد غير مكتمل"),
    el("div",{cls:"ob-body"},"أضف بيانات مشروع Firebase في ملف firebase-config.js ثم أعد النشر.")]));
}
function screenFatal(msg){
  mount(gateWrap([el("div",{cls:"ob-emoji"},"⚠️"),el("div",{cls:"ob-title"},"تعذّر التشغيل"),el("div",{cls:"ob-body"},msg)]));
}

function authErr(e){
  var c=(e&&e.code)||"";
  if(c==="auth/invalid-credential"||c==="auth/wrong-password"||c==="auth/user-not-found"||c==="auth/invalid-login-credentials") return "البريد أو كلمة المرور غير صحيحة";
  if(c==="auth/invalid-email") return "صيغة البريد غير صحيحة";
  if(c==="auth/too-many-requests") return "محاولات كثيرة — حاول بعد قليل";
  if(c==="auth/network-request-failed") return "لا يوجد اتصال بالإنترنت";
  if(c==="auth/missing-password") return "أدخل كلمة المرور";
  return "تعذّر الدخول ("+c+")";
}
function screenLogin(){
  var em=inpEl({type:"email",placeholder:"البريد الإلكتروني",cls:"inp inp-ltr",autocomplete:"username",inputmode:"email"});
  var pw=inpEl({type:"password",placeholder:"كلمة المرور",cls:"inp inp-ltr",autocomplete:"current-password"});
  var err=el("div",{cls:"gate-err"});
  var btn=el("button",{cls:"btn btn-accent"},"دخول");
  function doLogin(){
    var e=em.value.trim(),p=pw.value;
    if(!e||!p){err.textContent="أدخل البريد وكلمة المرور";return;}
    btn.disabled=true;err.textContent="";
    firebase.auth().signInWithEmailAndPassword(e,p).catch(function(x){btn.disabled=false;err.textContent=authErr(x);});
  }
  btn.addEventListener("click",doLogin);
  pw.addEventListener("keydown",function(ev){if(ev.keyCode===13)doLogin();});
  var forgot=el("button",{cls:"link-btn",onclick:function(){
    var e=em.value.trim();
    if(!e){err.textContent="اكتب بريدك أولاً ثم اضغط «نسيت كلمة المرور»";return;}
    firebase.auth().sendPasswordResetEmail(e).then(function(){toast("✓ أرسلنا رابط إعادة التعيين لبريدك");},function(x){err.textContent=authErr(x);});
  }},"نسيت كلمة المرور؟");
  var buy=el("button",{cls:"link-btn",onclick:function(){openWA("السلام عليكم، أرغب بالاشتراك في تطبيق ميزانية البيت");}},"ليس لديك اشتراك؟ اطلبه الآن");
  mount(gateWrap([
    el("div",{cls:"ob-emoji"},"💰"),
    el("div",{cls:"ob-title"},"ميزانية البيت"),
    el("div",{cls:"ob-body"},"سجّل الدخول بالحساب الذي وصلك عند الاشتراك.\n🔒 بياناتك المالية تبقى في جهازك فقط."),
    el("div",{cls:"gate-form"},[em,pw,err,btn]),
    forgot,buy
  ]));
}
function screenBlocked(res){
  var t={none:["🔑","لا يوجد اشتراك لهذا الحساب","تواصل معنا لتفعيل اشتراكك."],
    disabled:["⏸️","الاشتراك موقوف","تواصل معنا لإعادة التفعيل."],
    expired:res.trial?["🎁","انتهت الفترة التجريبية","نتمنى أن التجربة أعجبتك!\nبياناتك محفوظة ومشفّرة على جهازك، وتعود كما هي فور الاشتراك."]:["⏳","انتهى الاشتراك",res.exp?("انتهى بتاريخ "+dateLbl(res.exp)+".\nبياناتك محفوظة ومشفّرة على جهازك وستعود فور التجديد."):"جدّد اشتراكك للمتابعة."],
    devices:["📱","تجاوزت عدد الأجهزة","هذا الاشتراك مفعّل على "+(res.max||1)+" جهاز.\nتواصل معنا لنقل الاشتراك لهذا الجهاز."],
    offline:["📡","تحتاج اتصالاً بالإنترنت","مرّت مدة طويلة بدون التحقق من الاشتراك.\nاتصل بالإنترنت مرة واحدة وأعد المحاولة."]}[res.reason]||["⚠️","تعذّر التحقق",""];
  var email=USER?USER.email:"";
  mount(gateWrap([
    el("div",{cls:"ob-emoji"},t[0]),el("div",{cls:"ob-title"},t[1]),el("div",{cls:"ob-body"},t[2]),
    el("div",{cls:"gate-form"},[
      el("button",{cls:"btn btn-wa",onclick:function(){openWA("السلام عليكم، بخصوص اشتراك ميزانية البيت ("+t[1]+")\nالحساب: "+email);}},"💬 تواصل عبر واتساب"),
      el("button",{cls:"btn btn-ghost",onclick:function(){screenLoading("جاري التحقق…");checkLicense(USER).then(afterLicense);}},"🔄 إعادة المحاولة"),
      el("button",{cls:"btn btn-ghost",onclick:function(){firebase.auth().signOut();}},"تسجيل الخروج")
    ]),
    el("div",{cls:"ob-body",sty:{fontSize:"12px"}},email)
  ]));
}

/* PIN pad — calls onDone(pin, fail) ; fail() shakes & clears */
function pinPad(title,sub,onDone,extra){
  var val="",dots=el("div",{cls:"pin-dots"}),dotEls=[];
  for(var i=0;i<PIN_LEN;i++){var d=el("div",{cls:"pin-dot"});dotEls.push(d);dots.appendChild(d);}
  var msg=el("div",{cls:"gate-err"});
  var busy=false;
  function paint(){for(var i=0;i<PIN_LEN;i++)dotEls[i].className="pin-dot"+(i<val.length?" on":"");}
  function fail(m){busy=false;val="";paint();msg.textContent=m||"";dots.className="pin-dots shake";setTimeout(function(){dots.className="pin-dots";},400);}
  function press(k){
    if(busy)return;
    if(k==="del"){val=val.slice(0,-1);paint();return;}
    if(val.length>=PIN_LEN)return;
    val+=k;paint();msg.textContent="";
    if(val.length===PIN_LEN){busy=true;var v=val;setTimeout(function(){onDone(v,fail);},120);}
  }
  var pad=el("div",{cls:"pin-pad"});
  var keys=["1","2","3","4","5","6","7","8","9","",  "0","del"];
  for(var k=0;k<keys.length;k++){
    (function(key){
      if(key===""){pad.appendChild(el("div"));return;}
      pad.appendChild(el("button",{cls:"pin-key"+(key==="del"?" ghost":""),onclick:function(){press(key);}},key==="del"?"⌫":key));
    })(keys[k]);
  }
  var kids=[el("div",{cls:"ob-emoji",sty:{fontSize:"44px"}},"🔒"),el("div",{cls:"ob-title",sty:{fontSize:"19px"}},title),el("div",{cls:"ob-body"},sub||""),dots,msg,pad];
  if(extra) kids=kids.concat(extra);
  mount(gateWrap(kids));
}

/* ═══════════════ LICENSE ═══════════════ */
function checkLicense(user){
  var email=(user.email||"").toLowerCase();
  var ref=firebase.firestore().collection("licenses").doc(email);
  return withTimeout(ref.get({source:"server"}),12000).then(function(snap){
    if(!snap.exists) return {ok:false,reason:"none"};
    var d=snap.data();
    if(d.active===false) return {ok:false,reason:"disabled"};
    if(!d.expiresAt||d.expiresAt<Date.now()) return {ok:false,reason:"expired",exp:d.expiresAt,trial:!!d.trial};
    var devs=d.devices||{},id=deviceId(),p=Promise.resolve();
    if(!devs[id]){
      if(Object.keys(devs).length>=(d.maxDevices||1)) return {ok:false,reason:"devices",max:d.maxDevices};
      var upd={};upd["devices."+id]={name:deviceName(),added:Date.now()};
      p=ref.update(upd);devs[id]=1;
    }
    return p.then(function(){
      var n=Object.keys(devs).length;
      sv("mb2_lic",{email:email,until:Math.min(d.expiresAt,Date.now()+APP_SETTINGS.offlineDays*864e5),exp:d.expiresAt,maxD:d.maxDevices,devs:n,trial:!!d.trial});
      return {ok:true,lic:{email:email,expiresAt:d.expiresAt,maxDevices:d.maxDevices,devCount:n,name:d.name||"",trial:!!d.trial}};
    });
  }).catch(function(err){
    if(err&&err.reason) return err;
    if(err&&err.code==="permission-denied") return {ok:false,reason:"devices",max:"؟"};
    var c=ld("mb2_lic",null);
    if(c&&c.email===email&&Date.now()<c.until) return {ok:true,offline:true,lic:{email:email,expiresAt:c.exp,maxDevices:c.maxD,devCount:c.devs,trial:!!c.trial}};
    return {ok:false,reason:"offline"};
  });
}
function afterLicense(res){
  if(!res.ok){LIC=null;screenBlocked(res);return;}
  LIC=res.lic;LIC.offline=!!res.offline;
  openVault();
}

/* ═══════════════ VAULT ═══════════════ */
function adoptLocal(){
  /* first login after switching from local mode: move the local vault to this account */
  var lv=ld(LOCAL_NS+"vault",null);if(!lv)return;
  sv(NS+"vault",lv);var d=ld(LOCAL_NS+"data",null);if(d)sv(NS+"data",d);
  rm(LOCAL_NS+"vault");rm(LOCAL_NS+"data");
}
function openVault(){
  (LOCAL_MODE?Promise.resolve(null):sha256Hex((USER.email||"").toLowerCase())).then(function(h){
    NS=LOCAL_MODE?LOCAL_NS:"mb2_"+h.slice(0,16)+"_";
    if(!LOCAL_MODE&&!ld(NS+"vault",null)) adoptLocal();
    VAULT=ld(NS+"vault",null);
    if(!VAULT) return createVault();
    if(VAULT.mode==="pin") return screenLock();
    return unlockRaw(unb64(VAULT.raw));
  }).catch(function(e){screenFatal("خطأ في فتح البيانات: "+(e&&e.message||e));});
}
function createVault(){
  var raw=rnd(32),legacy=legacyState();
  VAULT={v:1,mode:"plain",raw:b64(raw)};
  sv(NS+"vault",VAULT);
  return importDataKey(raw).then(function(k){
    RAW=raw;DKEY=k;S=legacy||freshState();bindCats();
    return aesEnc(DKEY,enc.encode(JSON.stringify(S)));
  }).then(function(blob){
    sv(NS+"data",blob);
    if(legacy){clearLegacy();toast("✓ تم نقل بياناتك السابقة وتشفيرها");}
    startApp();
    if(legacy&&legacy.legacyPin){S.legacyPin=false;save();
      modal("🔒 قفل أقوى","كان القفل مفعّلاً في النسخة السابقة.\nالنسخة الجديدة تستخدم رمزاً من 6 أرقام يشفّر بياناتك. فعّله الآن؟",false,enablePinFlow,"تفعيل");}
  });
}
function unlockRaw(raw){
  return importDataKey(raw).then(function(k){
    var blob=ld(NS+"data",null);
    if(!blob) return {k:k,st:freshState()};
    return aesDec(k,blob).then(function(pt){return {k:k,st:JSON.parse(dec.decode(pt))};});
  }).then(function(r){
    RAW=raw;DKEY=r.k;S=r.st;bindCats();startApp();
  });
}
function lockNow(){
  S=null;RAW=null;DKEY=null;
  closeModal();document.getElementById("ask-overlay").classList.remove("show");document.getElementById("commit-overlay").classList.remove("show");
  screenLock();
}
function screenLock(){
  pinPad("أدخل رمز القفل","",function(pin,fail){
    if(Date.now()<pinLockUntil){fail("انتظر "+Math.ceil((pinLockUntil-Date.now())/1000)+" ثانية");return;}
    unwrapWith(pin,VAULT.wPin).then(function(raw){pinFails=0;return unlockRaw(raw);},function(){
      pinFails++;
      if(pinFails>=5){pinLockUntil=Date.now()+30000*(pinFails-4);fail("محاولات كثيرة — انتظر قليلاً");}
      else fail("رمز غير صحيح");
    });
  },[
    el("button",{cls:"link-btn",onclick:screenRecover},"نسيت الرمز؟"),
    LOCAL_MODE?null:el("button",{cls:"link-btn",sty:{color:"var(--text3)",fontSize:"12px"},onclick:function(){firebase.auth().signOut();}},"تسجيل الخروج")
  ]);
}
function screenRecover(){
  var q=VAULT.secQ!=null?SEC_QUESTIONS[VAULT.secQ]:"سؤال الأمان";
  var ans=inpEl({placeholder:"الإجابة",autocomplete:"off"});
  var err=el("div",{cls:"gate-err"});
  var btn=el("button",{cls:"btn btn-accent"},"تحقق");
  btn.addEventListener("click",function(){
    if(!ans.value.trim()){err.textContent="اكتب الإجابة";return;}
    btn.disabled=true;err.textContent="";
    unwrapWith(normAns(ans.value),VAULT.wSec).then(function(raw){
      RAW=raw;
      setNewPin(function(pin){
        wrapWith(pin,RAW).then(function(w){VAULT.wPin=w;sv(NS+"vault",VAULT);toast("✓ تم تعيين رمز جديد");unlockRaw(RAW);});
      },function(){screenLock();});
    },function(){btn.disabled=false;err.textContent="الإجابة غير صحيحة";});
  });
  mount(gateWrap([
    el("div",{cls:"ob-emoji"},"🗝️"),el("div",{cls:"ob-title"},"استعادة الرمز"),el("div",{cls:"ob-body"},q),
    el("div",{cls:"gate-form"},[ans,err,btn,el("button",{cls:"btn btn-ghost",onclick:screenLock},"رجوع")]),
    el("div",{cls:"ob-body",sty:{fontSize:"12px"}},"إذا نسيت الإجابة أيضاً، لا يمكن فتح البيانات المشفّرة —\nيمكنك فقط استرجاعها من نسخة احتياطية.")
  ]));
}
/* two-step new PIN entry */
function setNewPin(onSet,onCancel){
  var cancel=el("button",{cls:"link-btn",onclick:onCancel},"إلغاء");
  pinPad("رمز جديد ("+PIN_LEN+" أرقام)","اختر رمزاً لا يسهل تخمينه",function(p1,fail1){
    if(/^(\d)\1+$/.test(p1)||"0123456789".indexOf(p1)>=0||"9876543210".indexOf(p1)>=0){fail1("رمز ضعيف — تجنّب المتكرر والمتسلسل");return;}
    pinPad("أعد إدخال الرمز","",function(p2,fail){
      if(p1!==p2){fail("الرمزان غير متطابقين");return;}
      onSet(p1);
    },[el("button",{cls:"link-btn",onclick:onCancel},"إلغاء")]);
  },[cancel]);
}
function enablePinFlow(){
  setNewPin(function(pin){
    var qOpts=SEC_QUESTIONS;
    render();
    askSheet({title:"سؤال الأمان",sub:"يُستخدم لاستعادة الوصول إذا نسيت الرمز. احفظ الإجابة جيداً.",
      fields:[{type:"select",options:qOpts},{placeholder:"الإجابة"}],okLbl:"تفعيل القفل",
      onOk:function(v,close,err){
        if(normAns(v[1]).length<2){err("اكتب إجابة واضحة");return;}
        var newRaw=rnd(32),qi=parseInt(v[0],10);
        Promise.all([wrapWith(pin,newRaw),wrapWith(normAns(v[1]),newRaw),importDataKey(newRaw)]).then(function(r){
          /* rotate data key so the old plain-stored key becomes useless */
          RAW=newRaw;DKEY=r[2];
          VAULT={v:1,mode:"pin",wPin:r[0],wSec:r[1],secQ:qi};
          return aesEnc(DKEY,enc.encode(JSON.stringify(S))).then(function(blob){
            sv(NS+"data",blob);sv(NS+"vault",VAULT);close();toast("🔒 تم تفعيل القفل والتشفير");render();
          });
        }).catch(function(){err("حدث خطأ — حاول مرة أخرى");});
      }});
  },function(){render();});
}
function changePinFlow(){
  setNewPin(function(pin){
    wrapWith(pin,RAW).then(function(w){VAULT.wPin=w;sv(NS+"vault",VAULT);toast("✓ تم تغيير الرمز");render();});
  },function(){render();});
}
function disablePin(){
  modal("إيقاف قفل الرمز؟","سيفتح التطبيق مباشرة بدون رمز. تبقى البيانات مشفّرة لكن أي شخص يمسك الجهاز يستطيع فتحها.",false,function(){
    VAULT={v:1,mode:"plain",raw:b64(RAW)};sv(NS+"vault",VAULT);toast("تم إيقاف القفل");render();
  },"إيقاف");
}

/* ═══════════════ APP START ═══════════════ */
function startApp(){
  try{if(navigator.storage&&navigator.storage.persist)navigator.storage.persist();}catch(e){}
  applyAccent(S.accent);
  UI.month=thisMonth();
  if(!S.onboarded) UI.obStep=0;
  UI.view="home";render();
}

/* ═══════════════ COMMIT SHEET ═══════════════ */
function openCommitSheet(){
  var pending=pendingCommits();if(!pending.length)return;
  var total=0;for(var i=0;i<pending.length;i++)total+=pending[i].amount;
  document.getElementById("commit-subtitle").textContent=pending.length+" التزام بإجمالي "+fmt(total)+" "+CUR;
  var list=document.getElementById("commit-list");list.innerHTML="";
  for(var j=0;j<pending.length;j++){
    var c=pending[j],cat=getCat("expense",c.catId);
    list.appendChild(el("div",{sty:{display:"flex",alignItems:"center",padding:"12px 14px",background:"var(--surface2)",borderRadius:"12px",borderRight:"3px solid "+cat.c,marginBottom:"8px"}},[
      el("div",{sty:{fontSize:"22px",marginLeft:"12px"}},c.emoji||"💳"),
      el("div",{sty:{flex:"1",minWidth:"0"}},[el("div",{sty:{fontSize:"14px",fontWeight:"800"}},c.name),el("div",{sty:{fontSize:"11px",color:"var(--text3)"}},cat.em+" "+cat.lbl)]),
      el("div",{sty:{fontSize:"15px",fontWeight:"900",color:"var(--text)"}},fmt(c.amount))
    ]));
  }
  document.getElementById("commit-overlay").classList.add("show");
}
function closeCommitSheet(){document.getElementById("commit-overlay").classList.remove("show");}
document.getElementById("commit-apply-btn").addEventListener("click",function(){
  var m=thisMonth(),pending=pendingCommits(),ts=Date.now();
  for(var i=0;i<pending.length;i++){
    var c=pending[i];
    S.txs.push({id:"co_"+ts+"_"+i,type:"expense",catId:c.catId,label:c.name,amount:c.amount,date:today(),note:"التزام ثابت",isCommit:true});
    for(var j=0;j<S.commits.length;j++){if(S.commits[j].id===c.id){var am=(S.commits[j].appliedMonths||[]).slice();am.push(m);S.commits[j].appliedMonths=am;break;}}
  }
  save();closeCommitSheet();toast("✅ تم تطبيق "+pending.length+" التزام");render();
});
document.getElementById("commit-skip-btn").addEventListener("click",closeCommitSheet);
document.getElementById("commit-overlay").addEventListener("click",function(e){if(e.target.id==="commit-overlay")closeCommitSheet();});

/* ═══════════════ COMPONENTS ═══════════════ */
function tabBar(){
  var bar=el("div",{cls:"tabbar"});
  var tabs=[{id:"home",icon:"🏠",lbl:"الرئيسية",v:"home"},{id:"income",icon:"💰",lbl:"الدخل",v:"incList"},{id:"expense",icon:"💸",lbl:"المصروفات",v:"expList"},{id:"report",icon:"📊",lbl:"التقارير",v:"report"},{id:"more",icon:"⋯",lbl:"المزيد",v:"more"}];
  for(var i=0;i<tabs.length;i++){
    (function(t){
      bar.appendChild(el("button",{cls:"tab-btn"+(UI.tab===t.id?" active":""),onclick:function(){UI.tab=t.id;go(t.v);}},[el("span",{cls:"tab-icon"},t.icon),el("span",{cls:"tab-lbl"},t.lbl)]));
    })(tabs[i]);
  }
  return bar;
}
function monthScroller(active,onPick){
  var ms=el("div",{cls:"month-scroll"}),months=dataMonths();
  for(var i=0;i<months.length;i++){(function(m){ms.appendChild(el("button",{cls:"mtab"+(m===active?" active":""),onclick:function(){onPick(m);}},monthLbl(m)));})(months[i]);}
  return ms;
}
function donutChart(data,total,centerVal,centerLbl){
  var size=110,r=44,cx=55,cy=55,sw=14,circ=2*Math.PI*r,NSs="http://www.w3.org/2000/svg";
  var svg=document.createElementNS(NSs,"svg");
  svg.setAttribute("width",size);svg.setAttribute("height",size);svg.setAttribute("viewBox","0 0 "+size+" "+size);svg.style.transform="rotate(-90deg)";
  var bg=document.createElementNS(NSs,"circle");
  bg.setAttribute("cx",cx);bg.setAttribute("cy",cy);bg.setAttribute("r",r);bg.setAttribute("fill","none");bg.style.stroke="var(--surface2)";bg.setAttribute("stroke-width",sw);svg.appendChild(bg);
  var off=0;
  for(var i=0;i<data.length;i++){
    var d=data[i];if(!d.v)continue;
    var dash=(d.v/total)*circ,c=document.createElementNS(NSs,"circle");
    c.setAttribute("cx",cx);c.setAttribute("cy",cy);c.setAttribute("r",r);c.setAttribute("fill","none");c.setAttribute("stroke",d.color);c.setAttribute("stroke-width",sw);
    c.setAttribute("stroke-dasharray",dash+" "+(circ-dash));c.setAttribute("stroke-dashoffset",-off);svg.appendChild(c);off+=dash;
  }
  var w=el("div",{cls:"donut-wrap"});w.appendChild(svg);
  w.appendChild(el("div",{cls:"donut-center"},[el("div",{cls:"donut-center-val"},centerVal),el("div",{cls:"donut-center-lbl"},centerLbl)]));
  return w;
}
function banner(kind,msg,onClose,onClick){
  var b=el("div",{cls:"alert-banner alert-"+kind,sty:onClick?{cursor:"pointer"}:null,onclick:onClick||null},[el("div",{cls:"alert-msg"},msg)]);
  if(onClose) b.appendChild(el("button",{cls:"alert-x",onclick:function(e){e.stopPropagation();onClose();}},"✕"));
  return b;
}
/* per-category monthly caps */
function capStatus(st){
  var r=[];
  for(var i=0;i<EXP_CATS.length;i++){
    var c=EXP_CATS[i];if(!(c.cap>0))continue;
    var sp=st.byEC[c.id]||0;r.push({cat:c,cap:c.cap,spent:sp,pct:sp/c.cap*100});
  }
  r.sort(function(a,b){return b.pct-a.pct;});
  return r;
}
function capColor(p){return p>=100?"var(--expense)":p>=80?"var(--amber)":"var(--income)";}
function capBars(rows){
  var w=el("div",{cls:"bar-chart"});
  for(var i=0;i<rows.length;i++){
    (function(x){
      w.appendChild(el("div",{sty:{cursor:"pointer"},onclick:function(){UI.selectedCat=x.cat;go("catDetail");}},[
        el("div",{sty:{display:"flex",justifyContent:"space-between",fontSize:"12px",fontWeight:"700",marginBottom:"5px"}},[
          el("span",null,x.cat.em+" "+x.cat.lbl),
          el("span",{sty:{color:capColor(x.pct)}},fmt(x.spent)+" من "+fmt(x.cap))
        ]),
        el("div",{cls:"bar-track"},[el("div",{cls:"bar-fill",sty:{width:Math.min(100,x.pct)+"%",background:capColor(x.pct)}})])
      ]));
    })(rows[i]);
  }
  return w;
}
function pickCurrency(){
  var opts=[],cur=0;for(var i=0;i<CURRENCIES.length;i++){opts.push(CURRENCIES[i].lbl+" — "+CURRENCIES[i].code);if(CURRENCIES[i].code===S.currency.code)cur=i;}
  askSheet({title:"💱 العملة",sub:"تغيير العملة يغيّر طريقة العرض فقط ولا يحوّل المبالغ المسجّلة.",fields:[{type:"select",options:opts,value:String(cur)}],okLbl:"حفظ",
    onOk:function(v,close){S.currency=CURRENCIES[parseInt(v[0],10)];CUR=S.currency.lbl;save();close();toast("✓ العملة: "+S.currency.code);render();}});
}
function pickCycleDay(){
  var opts=["يوم 1 (الشهر الميلادي)"];for(var d=2;d<=28;d++)opts.push("يوم "+d);
  askSheet({title:"📅 بداية الشهر المالي",sub:"اختر اليوم الذي ينزل فيه راتبك. سيبدأ كل شهر من هذا اليوم في كل التقارير والحدود والالتزامات.",
    fields:[{type:"select",options:opts,value:String(cycDay()-1)}],okLbl:"حفظ",
    onOk:function(v,close){S.cycleDay=parseInt(v[0],10)+1;S.cycleTipOff=true;UI.month=thisMonth();save();close();toast("✓ الشهر المالي يبدأ يوم "+S.cycleDay);render();}});
}
function txRow(t,isLast){
  var cat=getCat(t.type,t.catId);
  return el("div",{cls:"tx-row",sty:{cursor:"pointer",borderBottom:isLast?"none":"1px solid var(--border)"},onclick:function(){UI.editTx=t;go("editTx");}},[
    el("div",{cls:"tx-icon",sty:{background:cat.c+"18"}},t.isCommit?"📋":cat.em),
    el("div",{cls:"tx-info"},[el("div",{cls:"tx-name"},t.label||cat.lbl),el("div",{cls:"tx-sub"},t.date+(t.isCommit?" · التزام ثابت":t.note?" · "+t.note:""))]),
    el("div",{cls:"tx-amt",sty:{color:t.type==="income"?"var(--income)":"var(--expense)"}},(t.type==="income"?"+":"-")+fmt(t.amount))
  ]);
}

/* ═══════════════ PAGE: ONBOARD ═══════════════ */
function pageOnboard(){
  var slides=[
    {em:"💰",title:"ميزانية البيت",body:"تتبّع دخلك ومصروفاتك بالدينار البحريني"},
    {em:"🔒",title:"خصوصيتك أولاً",body:"بياناتك المالية محفوظة ومشفّرة داخل جهازك فقط.\nلا نراها ولا تُرسل لأي خادم."},
    {em:"📋",title:"الالتزامات الثابتة",body:"سجّل إيجارك وأقساطك مرة واحدة وطبّقها كل شهر بضغطة"},
    {em:"📊",title:"تقارير واضحة",body:"رصيدك الشهري والسنوي ونسب إنفاقك في مكان واحد"}
  ];
  var s=slides[UI.obStep],dots=el("div",{cls:"ob-dots"});
  for(var i=0;i<slides.length;i++) dots.appendChild(el("div",{cls:"ob-dot"+(i===UI.obStep?" active":"")}));
  var kids=[el("div",{cls:"ob-emoji"},s.em),el("div",{cls:"ob-title"},s.title),el("div",{cls:"ob-body"},s.body),dots,
    el("button",{cls:"btn btn-accent",sty:{maxWidth:"300px"},onclick:function(){
      if(UI.obStep<slides.length-1){UI.obStep++;render();}else{S.onboarded=true;save();go("home");}
    }},UI.obStep<slides.length-1?"التالي":"ابدأ الآن ✓")];
  if(UI.obStep>0) kids.push(el("button",{cls:"link-btn",onclick:function(){UI.obStep--;render();}},"رجوع"));
  return gateWrap(kids);
}

/* ═══════════════ PAGE: HOME ═══════════════ */
function pageHome(){
  UI.tab="home";
  var ym=UI.month,st=monthStats(ym),page=el("div",{cls:"page"}),hdr=el("div",{cls:"hdr"});
  hdr.appendChild(el("div",{sty:{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"16px"}},[
    el("div",null,[el("div",{cls:"hdr-title"},"ميزانية البيت"),el("div",{sty:{fontSize:"13px",color:"rgba(255,255,255,.75)",fontWeight:"600"}},monthLbl(ym)+(periodRange(ym)?"  ·  "+periodRange(ym):""))]),
    el("button",{sty:{background:"rgba(255,255,255,.2)",border:"1.5px solid rgba(255,255,255,.35)",borderRadius:"12px",width:"44px",height:"44px",fontSize:"20px",color:"#fff"},onclick:function(){go("more");}},"⚙️")
  ]));
  var bc=el("div",{cls:"balance-card"}),bal=st.bal;
  bc.appendChild(el("div",{cls:"balance-main"},[el("span",{cls:"balance-num",sty:{color:bal<0?"#FCA5A5":"#fff"}},fmt(Math.abs(bal))),el("span",{cls:"balance-cur"},CUR)]));
  bc.appendChild(el("div",{cls:"balance-label"},bal>=0?"↑ الرصيد هذا الشهر":"↓ عجز هذا الشهر"));
  var grid=el("div",{sty:{display:"grid",gridTemplateColumns:"1fr 1px 1fr 1px 1fr 1px 1fr",alignItems:"center"}});
  function scol(l,v,c){return el("div",{cls:"scale-side",sty:{textAlign:"center",padding:"0 4px"}},[el("div",{cls:"scale-lbl"},l),el("div",{cls:"scale-val "+c},fmt(v))]);}
  grid.appendChild(scol("الدخل",st.inc,"inc"));grid.appendChild(el("div",{cls:"scale-divider"}));
  grid.appendChild(scol("ثابتة",st.commitExp,"com"));grid.appendChild(el("div",{cls:"scale-divider"}));
  grid.appendChild(scol("متاح",st.available,"inc"));grid.appendChild(el("div",{cls:"scale-divider"}));
  grid.appendChild(scol("مصاريف",st.freeExp,"exp"));
  bc.appendChild(grid);
  if(st.available>0){
    var pct=Math.min(100,(st.freeExp/st.available)*100);
    bc.appendChild(el("div",{cls:"scale-bar-wrap"},[el("div",{cls:"scale-bar-fill",sty:{width:pct+"%",background:pct>=100?"#FCA5A5":pct>80?"#FCD34D":"#6EE7B7"}})]));
    bc.appendChild(el("div",{sty:{display:"flex",justifyContent:"space-between",marginTop:"6px",fontSize:"11px",color:"rgba(255,255,255,.6)",fontWeight:"700"}},[
      el("span",null,Math.round(pct)+"% مُنفق من المتاح"),el("span",null,"متبقي "+fmt(Math.max(0,st.available-st.freeExp))+" "+CUR)]));
  }
  hdr.appendChild(bc);
  hdr.appendChild(monthScroller(ym,function(m){UI.month=m;go("home");}));
  page.appendChild(hdr);

  var body=el("div",{cls:"content"});

  /* subscription / trial notice */
  if(LIC&&LIC.expiresAt){
    var dl=daysLeft(LIC.expiresAt);
    if(LIC.trial) body.appendChild(banner(dl<=2?"warn":"info","🎁 فترة تجريبية — متبقي "+daysW(dl)+" · اضغط للاشتراك",null,function(){openWA("السلام عليكم، جرّبت تطبيق ميزانية البيت وأرغب بالاشتراك\nالحساب: "+LIC.email);}));
    else if(dl<=14) body.appendChild(banner(dl<=3?"over":"warn","⏳ اشتراكك ينتهي خلال "+daysW(dl)+" — اضغط للتجديد",null,function(){openWA("السلام عليكم، أرغب بتجديد اشتراك ميزانية البيت\nالحساب: "+LIC.email);}));
  }
  /* salary-cycle tip (once) */
  var tipShown=false;
  if(S.cycleDay==null&&!S.cycleTipOff){tipShown=true;
    body.appendChild(banner("info","📅 راتبك ينزل يوم 25 مثلاً؟ اجعل شهرك المالي يبدأ من يوم الراتب",function(){S.cycleTipOff=true;save();render();},pickCycleDay));
  }
  /* backup reminder */
  if(!tipShown&&S.txs.length&&(Date.now()-(S.lastBackup||S.createdAt||0))>BACKUP_DAYS*864e5){tipShown=true;
    body.appendChild(banner("info","💾 بياناتك محفوظة في هذا الجهاز فقط — خذ نسخة احتياطية الآن",function(){S.lastBackup=Date.now()-(BACKUP_DAYS-3)*864e5;save();render();},exportBackup));
  }
  /* PIN suggestion */
  if(!tipShown&&VAULT&&VAULT.mode!=="pin"&&!S.pinTipOff&&S.txs.length>=3){
    body.appendChild(banner("info","🔒 فعّل قفل الرمز لحماية بياناتك من أي شخص يمسك جهازك",function(){S.pinTipOff=true;save();render();},enablePinFlow));
  }

  var pending=ym===thisMonth()?pendingCommits():[];
  if(pending.length){
    var pt=0;for(var i=0;i<pending.length;i++)pt+=pending[i].amount;
    body.appendChild(el("div",{cls:"commit-banner",sty:{cursor:"pointer"},onclick:openCommitSheet},[
      el("div",{sty:{fontSize:"26px"}},"📋"),
      el("div",{cls:"commit-banner-info"},[el("div",{cls:"commit-banner-title"},"لديك "+pending.length+" التزام شهري"),el("div",{cls:"commit-banner-sub"},"إجمالي "+fmt(pt)+" "+CUR+" — اضغط للتطبيق")]),
      el("div",{sty:{fontSize:"18px",color:"rgba(255,255,255,.7)"}},"←")
    ]));
  }
  if(st.inc>0&&st.available>0){
    var p2=(st.freeExp/st.available)*100;
    if(p2>=100) body.appendChild(banner("over","🚨 تجاوزت المبلغ المتاح للإنفاق بـ "+fmt(st.freeExp-st.available)+" "+CUR));
    else if(p2>=80) body.appendChild(banner("warn","⚠️ استهلكت "+Math.round(p2)+"% من المبلغ المتاح للإنفاق"));
  }

  var capRows=capStatus(st);
  for(var cb=0;cb<capRows.length;cb++){
    if(capRows[cb].pct>=100) body.appendChild(banner("over","🚨 تجاوزت حد «"+capRows[cb].cat.lbl+"» بـ "+fmt(capRows[cb].spent-capRows[cb].cap)+" "+CUR,null,(function(c){return function(){UI.selectedCat=c;go("catDetail");};})(capRows[cb].cat)));
  }

  body.appendChild(el("div",{cls:"quick-bar"},[
    el("button",{cls:"quick-btn quick-inc",onclick:function(){UI.editTx=null;go("addInc");}},"💰 إضافة دخل"),
    el("button",{cls:"quick-btn quick-exp",onclick:function(){UI.editTx=null;go("addExp");}},"💸 إضافة مصروف")
  ]));

  /* debts summary */
  var dtH=debtTotals();
  if(dtH.open){
    body.appendChild(el("div",{cls:"card",sty:{cursor:"pointer"},onclick:function(){go("debts");}},[el("div",{cls:"tx-row"},[
      el("div",{cls:"tx-icon",sty:{background:"var(--surface2)"}},"🤝"),
      el("div",{cls:"tx-info"},[el("div",{cls:"tx-name"},"الديون"),el("div",{cls:"tx-sub",sty:dtH.overdue?{color:"var(--expense)",fontWeight:"700"}:null},dtH.overdue?("⚠️ "+dtH.overdue+" متأخر عن الاستحقاق"):(dtH.open+" دين مفتوح"))]),
      el("div",{sty:{textAlign:"left",fontSize:"12px",fontWeight:"800",lineHeight:"1.6"}},[el("div",{sty:{color:"var(--income)"}},"لك "+fmt(dtH.inn)),el("div",{sty:{color:"var(--expense)"}},"عليك "+fmt(dtH.out))])
    ])]));
  }
  if(capRows.length){
    body.appendChild(secTitle("حدود الإنفاق"));
    body.appendChild(el("div",{cls:"card card-p"},[capBars(capRows)]));
  }

  var expData=[];
  for(var k=0;k<EXP_CATS.length;k++){var v=st.byEC[EXP_CATS[k].id]||0;if(v>0)expData.push({label:EXP_CATS[k].lbl,color:EXP_CATS[k].c,v:v});}
  expData.sort(function(a,b){return b.v-a.v;});
  var top5=expData.slice(0,5);
  if(top5.length){
    body.appendChild(secTitle("توزيع المصروفات"));
    var legend=el("div",{cls:"chart-legend"});
    for(var q=0;q<top5.length;q++) legend.appendChild(el("div",{cls:"legend-row"},[el("div",{cls:"legend-dot",sty:{background:top5[q].color}}),el("div",{cls:"legend-lbl"},top5[q].label),el("div",{cls:"legend-val"},fmt(top5[q].v))]));
    body.appendChild(el("div",{cls:"card"},[el("div",{cls:"chart-wrap"},[donutChart(top5,st.exp,fmt(st.exp),"مصروفات"),legend])]));
  }

  var recent=st.txs.slice().sort(function(a,b){return a.date<b.date?1:a.date>b.date?-1:0;}).slice(0,8);
  if(recent.length){
    body.appendChild(secTitle("آخر المعاملات"));
    var rc=el("div",{cls:"card"});
    for(var r=0;r<recent.length;r++) rc.appendChild(txRow(recent[r],r===recent.length-1));
    body.appendChild(rc);
  }
  if(!st.txs.length&&!pending.length){
    body.appendChild(el("div",{cls:"empty"},[el("div",{cls:"empty-icon"},"📊"),el("div",{cls:"empty-title"},"لا توجد معاملات"),el("div",{cls:"empty-body"},"اضغط «إضافة دخل» أو «إضافة مصروف» للبداية")]));
  }
  page.appendChild(body);page.appendChild(tabBar());
  return page;
}

/* ═══════════════ PAGE: TX LIST ═══════════════ */
function pageTxList(type){
  UI.tab=type==="income"?"income":"expense";
  var ym=UI.month,st=monthStats(ym),total=type==="income"?st.inc:st.exp,cats=type==="income"?INC_CATS:EXP_CATS,byC=type==="income"?st.byIC:st.byEC;
  var txs=st.txs.filter(function(t){return t.type===type;}).sort(function(a,b){return a.date<b.date?1:a.date>b.date?-1:0;});
  var page=el("div",{cls:"page",sty:{paddingBottom:"150px"}}),hdr=el("div",{cls:"hdr"});
  hdr.appendChild(el("div",{sty:{marginBottom:"16px"}},[
    el("div",{cls:"hdr-title"},type==="income"?"مصادر الدخل":"تفاصيل المصروفات"),
    el("div",{sty:{fontSize:"26px",fontWeight:"900",color:"#fff"}},fmt(total)+" "+CUR)
  ]));
  hdr.appendChild(monthScroller(ym,function(m){UI.month=m;go(type==="income"?"incList":"expList");}));
  page.appendChild(hdr);
  var body=el("div",{cls:"content"});

  if(type==="expense"&&st.commitExp>0){
    var sr=el("div",{cls:"stats-row"}),sd=[{l:"الإجمالي",v:st.exp,c:"var(--expense)"},{l:"التزامات",v:st.commitExp,c:"var(--commit)"},{l:"مصاريف عادية",v:st.freeExp,c:"var(--text)"}];
    for(var i=0;i<sd.length;i++) sr.appendChild(el("div",{cls:"stat-card"},[el("div",{cls:"stat-lbl"},sd[i].l),el("div",{cls:"stat-val",sty:{color:sd[i].c,fontSize:"14px"}},fmt(sd[i].v)),el("div",{cls:"stat-cur"},CUR)]));
    body.appendChild(sr);
  }

  var ct=[];
  for(var j=0;j<cats.length;j++){var v=byC[cats[j].id]||0;if(v>0)ct.push({cat:cats[j],v:v});}
  ct.sort(function(a,b){return b.v-a.v;});
  if(ct.length){
    body.appendChild(secTitle("حسب الفئة"));
    var cc=el("div",{cls:"card"});
    for(var k=0;k<ct.length;k++){
      (function(x,last){
        var hasCap=type==="expense"&&x.cat.cap>0,cp=hasCap?x.v/x.cat.cap*100:0;
        var sub=(total>0?Math.round(x.v/total*100):0)+"% من الإجمالي"+(hasCap?"  ·  الحد "+fmt(x.cat.cap):"");
        var info=el("div",{cls:"tx-info"},[el("div",{cls:"tx-name"},x.cat.lbl),el("div",{cls:"tx-sub",sty:hasCap&&cp>=80?{color:capColor(cp),fontWeight:"700"}:null},sub)]);
        if(hasCap) info.appendChild(el("div",{cls:"bar-track",sty:{height:"5px",marginTop:"5px"}},[el("div",{cls:"bar-fill",sty:{width:Math.min(100,cp)+"%",background:capColor(cp)}})]));
        cc.appendChild(el("div",{cls:"tx-row",sty:{cursor:type==="expense"?"pointer":"default",borderBottom:last?"none":"1px solid var(--border)"},onclick:type==="expense"?function(){UI.selectedCat=x.cat;go("catDetail");}:null},[
          el("div",{cls:"tx-icon",sty:{background:x.cat.c+"18"}},x.cat.em),
          info,
          el("div",{cls:"tx-amt",sty:{color:"var(--text)"}},fmt(x.v))
        ]));
      })(ct[k],k===ct.length-1);
    }
    body.appendChild(cc);
  }
  if(txs.length){
    var ttl=secTitle("جميع المعاملات ("+txs.length+")");
    body.appendChild(ttl);
    var srch=inpEl({type:"search",placeholder:"🔍 ابحث بالوصف أو الفئة أو المبلغ",autocomplete:"off"});
    var tc=el("div",{cls:"card"});
    var drawList=function(){
      var q=srch.value.trim().toLowerCase(),f=[];
      for(var n=0;n<txs.length;n++){
        var t=txs[n],cat=getCat(t.type,t.catId);
        if(!q||((t.label||"")+" "+(t.note||"")+" "+cat.lbl+" "+fmt(t.amount)+" "+t.amount+" "+t.date).toLowerCase().indexOf(q)>=0) f.push(t);
      }
      tc.innerHTML="";
      for(var m=0;m<f.length;m++) tc.appendChild(txRow(f[m],m===f.length-1));
      if(!f.length) tc.appendChild(el("div",{sty:{padding:"18px",textAlign:"center",color:"var(--text3)",fontSize:"13px"}},"لا توجد نتائج"));
      var sm=0;for(var s2=0;s2<f.length;s2++)sm+=f[s2].amount;
      ttl.textContent=q?("النتائج ("+f.length+") · "+fmt(sm)+" "+CUR):("جميع المعاملات ("+txs.length+")");
    };
    srch.addEventListener("input",drawList);
    if(txs.length>=5) body.appendChild(srch);
    body.appendChild(tc);drawList();
  } else {
    body.appendChild(el("div",{cls:"empty"},[el("div",{cls:"empty-icon"},type==="income"?"💰":"💸"),el("div",{cls:"empty-title"},type==="income"?"لا يوجد دخل":"لا توجد مصروفات"),el("div",{cls:"empty-body"},"اضغط الزر أسفل للإضافة")]));
  }
  page.appendChild(body);
  page.appendChild(el("button",{cls:"btn",sty:{position:"fixed",bottom:"calc(78px + env(safe-area-inset-bottom))",left:"50%",transform:"translateX(-50%)",width:"calc(100% - 32px)",maxWidth:"398px",background:type==="income"?"var(--income)":"var(--expense)",boxShadow:"0 4px 20px rgba(0,0,0,.18)",zIndex:"50"},
    onclick:function(){UI.editTx=null;go(type==="income"?"addInc":"addExp");}},type==="income"?"＋ إضافة دخل":"＋ إضافة مصروف"));
  page.appendChild(tabBar());
  return page;
}

/* ═══════════════ PAGE: ADD/EDIT TX ═══════════════ */
function catPicker(cats,curId,onPick){
  var g=el("div",{cls:"cat-grid"});
  function paint(){
    var ch=g.childNodes;
    for(var i=0;i<ch.length;i++){var c=cats[i],a=c.id===curId;ch[i].style.borderColor=a?c.c:"";ch[i].style.background=a?c.c+"15":"";ch[i].style.color=a?"var(--text)":"";}
  }
  for(var i=0;i<cats.length;i++){(function(c){g.appendChild(el("button",{cls:"cat-chip",onclick:function(){curId=c.id;onPick(c.id);paint();}},c.em+" "+c.lbl));})(cats[i]);}
  g.setCat=function(id){curId=id;onPick(id);paint();};
  paint();return g;
}
function amountField(val){
  var w=el("div",{sty:{position:"relative"}});
  var i=inpEl({type:"number",step:curDec()===2?"0.01":"0.001",inputmode:"decimal",value:val?String(val):"",placeholder:curDec()===2?"0.00":"0.000",cls:"inp inp-big",sty:{paddingLeft:"52px"}});
  w.appendChild(i);w.appendChild(el("span",{sty:{position:"absolute",left:"16px",top:"50%",transform:"translateY(-50%)",fontSize:"13px",color:"var(--text3)",fontWeight:"700",pointerEvents:"none"}},CUR));
  return {wrap:w,inp:i};
}
function pageAETx(type){
  var isEdit=!!UI.editTx;if(isEdit)type=UI.editTx.type;
  var f=isEdit?UI.editTx:{type:type,catId:(type==="income"?INC_CATS:EXP_CATS)[0].id,label:"",amount:"",date:today(),note:""};
  var cats=type==="income"?INC_CATS:EXP_CATS,curCat=f.catId,back=type==="income"?"incList":"expList";
  var page=el("div",{sty:{minHeight:"100vh",paddingBottom:"60px"}});
  page.appendChild(hdrBar(isEdit?"تعديل المعاملة":(type==="income"?"إضافة دخل":"إضافة مصروف"),back));
  var body=el("div",{cls:"content"});
  /* amount first — keyboard opens immediately */
  body.appendChild(secTitle("المبلغ ("+CUR+")"));
  var amt=amountField(isEdit?f.amount:"");body.appendChild(amt.wrap);
  if(!isEdit) UI.focusEl=amt.inp;
  /* quick-fill from recent entries */
  var lbl=inpEl({value:f.label||"",placeholder:type==="income"?"مثال: راتب الشهر":"مثال: مشتريات الأسبوع"});
  var picker=catPicker(cats,curCat,function(id){curCat=id;});
  if(!isEdit){
    var seen={},recent=[],all=S.txs.slice().sort(function(a,b){return a.date<b.date?1:a.date>b.date?-1:0;});
    for(var r=0;r<all.length&&recent.length<6;r++){
      var t=all[r];if(t.type!==type||t.isCommit)continue;
      var key=t.catId+"|"+(t.label||"");if(seen[key])continue;seen[key]=1;recent.push(t);
    }
    if(recent.length){
      body.appendChild(secTitle("إدخال سريع"));
      var qw=el("div",{cls:"wrap-grid"});
      for(var q=0;q<recent.length;q++){
        (function(t){
          var c=getCat(type,t.catId);
          qw.appendChild(el("button",{cls:"cat-chip",onclick:function(){
            picker.setCat(t.catId);lbl.value=t.label||"";amt.inp.value=String(t.amount);amt.inp.focus();amt.inp.select();
          }},c.em+" "+(t.label||c.lbl)+" · "+fmt(t.amount)));
        })(recent[q]);
      }
      body.appendChild(qw);
    }
  }
  body.appendChild(secTitle("الفئة"));
  body.appendChild(picker);
  body.appendChild(secTitle("الوصف (اختياري)"));
  body.appendChild(lbl);
  body.appendChild(secTitle("التاريخ"));
  var dt=inpEl({type:"date",value:f.date||today()});body.appendChild(dt);
  body.appendChild(secTitle("ملاحظة (اختياري)"));
  var note=inpEl({value:f.note||"",placeholder:"أي تفاصيل إضافية"});body.appendChild(note);
  function doSave(again){
    var a=parseFloat(amt.inp.value);if(!a||a<=0){toast("أدخل مبلغاً صحيحاً");amt.inp.focus();return;}
    var d=dt.value||today();
    if(isEdit){for(var i=0;i<S.txs.length;i++){if(S.txs[i].id===f.id){S.txs[i]=Object.assign({},S.txs[i],{catId:curCat,label:lbl.value.trim(),amount:a,date:d,note:note.value.trim()});break;}}}
    else S.txs.push({id:uid(),type:type,catId:curCat,label:lbl.value.trim(),amount:a,date:d,note:note.value.trim()});
    UI.month=periodOf(d);save();
    if(type==="expense"){
      var c=getCat("expense",curCat);
      if(c.cap>0){var sp=monthStats(periodOf(d)).byEC[c.id]||0,p=sp/c.cap*100;
        if(p>=100){toast("🚨 تجاوزت حد «"+c.lbl+"»");}else if(p>=80){toast("⚠️ «"+c.lbl+"» وصلت "+Math.round(p)+"% من الحد");}else toast(isEdit?"✓ تم الحفظ":"✓ تمت الإضافة");}
      else toast(isEdit?"✓ تم الحفظ":"✓ تمت الإضافة");
    } else toast(isEdit?"✓ تم الحفظ":"✓ تمت الإضافة");
    if(again){UI.editTx=null;go(type==="income"?"addInc":"addExp");} else go(back);
  }
  amt.inp.addEventListener("keydown",function(ev){if(ev.keyCode===13)doSave(false);});
  var row=el("div",{cls:"btn-row"});
  row.appendChild(el("button",{cls:"btn",sty:{background:type==="income"?"var(--income)":"var(--expense)"},onclick:function(){doSave(false);}},isEdit?"💾 حفظ":"✅ إضافة"));
  if(!isEdit) row.appendChild(el("button",{cls:"btn btn-ghost",onclick:function(){doSave(true);}},"＋ حفظ وإضافة أخرى"));
  if(isEdit){
    row.appendChild(el("button",{cls:"btn btn-danger",sty:{width:"auto",padding:"14px 18px"},onclick:function(){
      modal("حذف المعاملة؟",f.label||"",false,function(){S.txs=S.txs.filter(function(t){return t.id!==f.id;});save();toast("تم الحذف");go(back);});
    }},"🗑️"));
  }
  body.appendChild(row);page.appendChild(body);return page;
}

/* ═══════════════ PAGE: COMMITMENTS ═══════════════ */
function pageCommits(){
  var page=el("div",{sty:{minHeight:"100vh",paddingBottom:"100px"}}),hdr=hdrBar("الالتزامات الثابتة","more"),tot=totalCommits();
  hdr.appendChild(el("div",{sty:{fontSize:"13px",color:"rgba(255,255,255,.75)",marginTop:"8px"}},[S.commits.length+" التزام  ·  إجمالي شهري: ",el("span",{sty:{fontWeight:"900",color:"#fff"}},fmt(tot)+" "+CUR)]));
  page.appendChild(hdr);
  var body=el("div",{cls:"content"});
  if(!S.commits.length){
    body.appendChild(el("div",{cls:"empty"},[el("div",{cls:"empty-icon"},"📋"),el("div",{cls:"empty-title"},"لا توجد التزامات بعد"),el("div",{cls:"empty-body"},"أضف إيجارك وأقساطك واشتراكاتك\nوطبّقها كل شهر بضغطة واحدة")]));
  } else {
    var m=thisMonth(),card=el("div",{cls:"card"});
    for(var i=0;i<S.commits.length;i++){
      (function(c,last){
        var cat=getCat("expense",c.catId),applied=c.appliedMonths&&c.appliedMonths.indexOf(m)>=0;
        card.appendChild(el("div",{cls:"tx-row",sty:{cursor:"pointer",borderBottom:last?"none":"1px solid var(--border)",borderRight:"3px solid "+cat.c},onclick:function(){UI.editCommit=Object.assign({},c);go("editCommit");}},[
          el("div",{sty:{fontSize:"22px"}},c.emoji||"💳"),
          el("div",{cls:"tx-info"},[el("div",{cls:"tx-name"},c.name),el("div",{cls:"tx-sub"},cat.em+" "+cat.lbl+"  ·  "+(applied?"✅ طُبّق هذا الشهر":"⏳ لم يُطبَّق بعد"))]),
          el("div",{cls:"tx-amt",sty:{color:"var(--text)"}},fmt(c.amount))
        ]));
      })(S.commits[i],i===S.commits.length-1);
    }
    card.appendChild(el("div",{sty:{display:"flex",justifyContent:"space-between",padding:"12px 16px",background:"var(--surface2)",borderTop:"1px solid var(--border)"}},[el("span",{sty:{fontSize:"13px",fontWeight:"800",color:"var(--text2)"}},"الإجمالي الشهري"),el("span",{sty:{fontSize:"16px",fontWeight:"900"}},fmt(tot)+" "+CUR)]));
    body.appendChild(card);
    var pending=pendingCommits();
    if(pending.length) body.appendChild(el("button",{cls:"btn btn-commit",onclick:openCommitSheet},"📋 تطبيق "+pending.length+" التزام هذا الشهر"));
    else body.appendChild(banner("info","✅ تم تطبيق جميع الالتزامات هذا الشهر"));
  }
  page.appendChild(body);
  page.appendChild(el("button",{cls:"btn btn-commit",sty:{position:"fixed",bottom:"calc(20px + env(safe-area-inset-bottom))",left:"50%",transform:"translateX(-50%)",width:"calc(100% - 32px)",maxWidth:"398px",boxShadow:"0 4px 20px rgba(124,58,237,.35)",zIndex:"50"},onclick:function(){UI.editCommit=null;go("editCommit");}},"＋ إضافة التزام"));
  return page;
}
function pageAECommit(){
  var isEdit=!!UI.editCommit,f=isEdit?UI.editCommit:{name:"",amount:"",catId:EXP_CATS[0].id,emoji:"💳",appliedMonths:[]};
  var curCat=f.catId,curEmoji=f.emoji||"💳";
  var page=el("div",{sty:{minHeight:"100vh",paddingBottom:"80px"}});
  page.appendChild(hdrBar(isEdit?"تعديل الالتزام":"التزام جديد","commitments"));
  var body=el("div",{cls:"content"});
  body.appendChild(secTitle("الفئة"));
  body.appendChild(catPicker(EXP_CATS,curCat,function(id){curCat=id;}));
  body.appendChild(secTitle("اسم الالتزام"));
  var ni=inpEl({value:f.name||"",placeholder:"مثال: إيجار البيت، قسط السيارة"});body.appendChild(ni);
  body.appendChild(secTitle("المبلغ الشهري ("+CUR+")"));
  var amt=amountField(f.amount);body.appendChild(amt.wrap);
  body.appendChild(secTitle("الأيقونة"));
  var ep=el("div",{cls:"wrap-grid"}),btns=[];
  for(var i=0;i<COMMIT_EMOJIS.length;i++){
    (function(em){
      var b=el("button",{sty:{width:"42px",height:"42px",borderRadius:"10px",border:"2px solid "+(curEmoji===em?"var(--commit)":"var(--border)"),background:curEmoji===em?"var(--commit-bg)":"var(--surface2)",fontSize:"20px"},onclick:function(){
        curEmoji=em;for(var j=0;j<btns.length;j++){btns[j].style.borderColor="var(--border)";btns[j].style.background="var(--surface2)";}
        b.style.borderColor="var(--commit)";b.style.background="var(--commit-bg)";}},em);
      btns.push(b);ep.appendChild(b);
    })(COMMIT_EMOJIS[i]);
  }
  body.appendChild(ep);
  var row=el("div",{cls:"btn-row"});
  row.appendChild(el("button",{cls:"btn btn-commit",onclick:function(){
    var name=ni.value.trim();if(!name){toast("أدخل اسم الالتزام");return;}
    var a=parseFloat(amt.inp.value);if(!a||a<=0){toast("أدخل مبلغاً صحيحاً");return;}
    var obj={id:isEdit?f.id:uid(),name:name,amount:a,catId:curCat,emoji:curEmoji,appliedMonths:isEdit?(f.appliedMonths||[]):[]};
    if(isEdit){for(var i=0;i<S.commits.length;i++)if(S.commits[i].id===f.id){S.commits[i]=obj;break;}}else S.commits.push(obj);
    save();toast(isEdit?"✓ تم الحفظ":"✓ تمت الإضافة");go("commitments");
  }},isEdit?"💾 حفظ":"✅ إضافة"));
  if(isEdit){
    row.appendChild(el("button",{cls:"btn btn-danger",sty:{width:"auto",padding:"14px 18px"},onclick:function(){
      modal("حذف الالتزام؟",f.name,false,function(){S.commits=S.commits.filter(function(c){return c.id!==f.id;});save();toast("تم الحذف");go("commitments");});
    }},"🗑️"));
  }
  body.appendChild(row);page.appendChild(body);return page;
}

/* ═══════════════ PAGE: REPORT ═══════════════ */
/* ═══════════════ DEBTS (لي / علي) ═══════════════
   d = {id, dir:"in"(لي عند الناس)|"out"(علي للناس), name, amount, date, due, note,
        pays:[{id,amount,date,txId}], link:bool, txId, closed:bool}
   link=true → creating the debt records a tx (lend=expense, borrow=income),
               every payment records the opposite tx. Deleting removes them. */
function debtPaid(d){var s=0,p=d.pays||[];for(var i=0;i<p.length;i++)s+=p[i].amount;return s;}
function debtLeft(d){return Math.max(0,Math.round((d.amount-debtPaid(d))*1000)/1000);}
function debtOverdue(d){return !d.closed&&d.due&&d.due<today()&&debtLeft(d)>0;}
function debtTotals(){
  var r={inn:0,out:0,overdue:0,open:0};
  for(var i=0;i<S.debts.length;i++){var d=S.debts[i];if(d.closed)continue;r.open++;
    if(d.dir==="in")r.inn+=debtLeft(d);else r.out+=debtLeft(d);if(debtOverdue(d))r.overdue++;}
  return r;
}
function findDebt(id){for(var i=0;i<S.debts.length;i++)if(S.debts[i].id===id)return S.debts[i];return null;}
function debtCat(type){
  if(type==="expense")return getCat("expense","debt").id==="debt"?"debt":EXP_CATS[EXP_CATS.length-1].id;
  return INC_CATS[INC_CATS.length-1].id;
}
function linkTx(id,type,amount,date,label){
  var t=null;for(var i=0;i<S.txs.length;i++)if(S.txs[i].id===id){t=S.txs[i];break;}
  if(!t){t={id:id,type:type,catId:debtCat(type),note:"دين"};S.txs.push(t);}
  t.amount=amount;t.date=date;t.label=label;t.type=type;
}
function unlinkTx(id){if(!id)return;S.txs=S.txs.filter(function(t){return t.id!==id;});}
/* lend(in)=money leaves me → expense; borrow(out)=money comes in → income. Payments are the reverse. */
function debtOpenType(d){return d.dir==="in"?"expense":"income";}
function debtPayType(d){return d.dir==="in"?"income":"expense";}
function syncDebtLinks(d){
  if(d.link){
    if(!d.txId)d.txId="dbt_"+d.id;
    linkTx(d.txId,debtOpenType(d),d.amount,d.date,(d.dir==="in"?"سلفة لـ ":"سلفة من ")+d.name);
    for(var i=0;i<(d.pays||[]).length;i++){var p=d.pays[i];if(!p.txId)p.txId="dbp_"+p.id;
      linkTx(p.txId,debtPayType(d),p.amount,p.date,(d.dir==="in"?"سداد من ":"سداد لـ ")+d.name);}
  } else {
    unlinkTx(d.txId);d.txId=null;
    for(var j=0;j<(d.pays||[]).length;j++){unlinkTx(d.pays[j].txId);d.pays[j].txId=null;}
  }
}
function debtRow(d,last){
  var left=debtLeft(d),pct=d.amount>0?Math.min(100,debtPaid(d)/d.amount*100):0,col=d.dir==="in"?"var(--income)":"var(--expense)";
  var sub=d.closed?"✅ مسدّد"+(d.closedAt?" · "+dsLbl(d.closedAt):""):(debtOverdue(d)?"⚠️ متأخر — الاستحقاق "+dsLbl(d.due):d.due?"الاستحقاق "+dsLbl(d.due):"منذ "+dsLbl(d.date));
  var info=el("div",{cls:"tx-info"},[el("div",{cls:"tx-name"},d.name),el("div",{cls:"tx-sub",sty:debtOverdue(d)?{color:"var(--expense)",fontWeight:"700"}:null},sub)]);
  if(!d.closed&&debtPaid(d)>0) info.appendChild(el("div",{cls:"bar-track",sty:{height:"5px",marginTop:"5px"}},[el("div",{cls:"bar-fill",sty:{width:pct+"%",background:col}})]));
  return el("div",{cls:"tx-row",sty:{cursor:"pointer",borderBottom:last?"none":"1px solid var(--border)",opacity:d.closed?".6":"1"},onclick:function(){UI.debtId=d.id;go("debtDetail");}},[
    el("div",{cls:"tx-icon",sty:{background:d.dir==="in"?"var(--income-bg)":"var(--expense-bg)"}},d.dir==="in"?"💚":"❤️"),
    info,
    el("div",{sty:{textAlign:"left",flexShrink:"0"}},[
      el("div",{cls:"tx-amt",sty:{color:d.closed?"var(--text3)":col}},fmt(d.closed?d.amount:left)),
      (!d.closed&&debtPaid(d)>0)?el("div",{sty:{fontSize:"10px",color:"var(--text3)"}},"من "+fmt(d.amount)):null
    ])
  ]);
}
function pageDebts(){
  var dir=UI.debtTab||"in",tot=debtTotals(),net=tot.inn-tot.out;
  var page=el("div",{sty:{minHeight:"100vh",paddingBottom:"100px"}}),hdr=hdrBar("الديون","more");
  var sr=el("div",{cls:"stats-row",sty:{marginTop:"14px"}});
  function hs(l,v,c){return el("div",{sty:{background:"rgba(255,255,255,.14)",borderRadius:"12px",padding:"10px 8px",textAlign:"center"}},[el("div",{sty:{fontSize:"10px",color:"rgba(255,255,255,.75)",fontWeight:"700"}},l),el("div",{sty:{fontSize:"15px",fontWeight:"900",color:c}},fmt(v))]);}
  sr.appendChild(hs("💚 لي عند الناس",tot.inn,"#6EE7B7"));sr.appendChild(hs("❤️ علي للناس",tot.out,"#FCA5A5"));
  sr.appendChild(hs(net>=0?"الصافي لي":"الصافي علي",Math.abs(net),"#fff"));
  hdr.appendChild(sr);page.appendChild(hdr);
  var body=el("div",{cls:"content"});
  var seg=el("div",{cls:"seg"}),tabs=[["in","💚 لي عند الناس"],["out","❤️ علي للناس"]];
  function odCount(dd){var c=0;for(var z=0;z<S.debts.length;z++)if(S.debts[z].dir===dd&&debtOverdue(S.debts[z]))c++;return c;}
  for(var i=0;i<tabs.length;i++){(function(t){seg.appendChild(el("button",{cls:dir===t[0]?"on":"",onclick:function(){UI.debtTab=t[0];render();}},t[1]+(odCount(t[0])?" ⚠️":"")));})(tabs[i]);}
  body.appendChild(seg);
  body.appendChild(el("div",{sty:{fontSize:"12px",color:"var(--text3)",textAlign:"center",marginTop:"6px"}},dir==="in"?"فلوس أقرضتها وتنتظر ترجع (أنت الدائن)":"فلوس استلفتها ولازم ترجّعها (أنت المدين)"));
  var odHere=odCount(dir);
  if(odHere) body.appendChild(banner("over",dir==="in"?"⚠️ "+odHere+" دين لك تأخّر سداده عن موعده":"⚠️ عليك "+odHere+" دين فات موعد سداده"));
  var list=S.debts.filter(function(d){return d.dir===dir;});
  var open=list.filter(function(d){return !d.closed;}).sort(function(a,b){var ao=debtOverdue(a)?0:1,bo=debtOverdue(b)?0:1;if(ao!==bo)return ao-bo;var ad=a.due||"9",bd=b.due||"9";return ad<bd?-1:ad>bd?1:(a.date<b.date?1:-1);});
  var done=list.filter(function(d){return d.closed;}).sort(function(a,b){return (a.closedAt||"")<(b.closedAt||"")?1:-1;});
  if(!open.length&&!done.length){
    body.appendChild(el("div",{cls:"empty"},[el("div",{cls:"empty-icon"},dir==="in"?"💚":"❤️"),el("div",{cls:"empty-title"},dir==="in"?"لا أحد عليه فلوس لك":"ما عليك ديون"),el("div",{cls:"empty-body"},"اضغط الزر أسفل لإضافة دين")]));
  }
  if(open.length){
    var oc=el("div",{cls:"card"});for(var j=0;j<open.length;j++)oc.appendChild(debtRow(open[j],j===open.length-1));
    body.appendChild(secTitle("قائمة ("+open.length+")"));body.appendChild(oc);
  }
  /* per-person net when a name appears more than once */
  var per={},names=[];
  for(var k=0;k<S.debts.length;k++){var d=S.debts[k];if(d.closed)continue;var key=d.name.trim();
    if(!per[key]){per[key]={n:0,v:0};names.push(key);}per[key].n++;per[key].v+=(d.dir==="in"?1:-1)*debtLeft(d);}
  var multi=names.filter(function(n){return per[n].n>1;});
  if(multi.length){
    body.appendChild(secTitle("الصافي حسب الشخص"));var pc=el("div",{cls:"card"});
    for(var m=0;m<multi.length;m++){var v=per[multi[m]].v;
      pc.appendChild(el("div",{cls:"kv"},[el("span",{cls:"kv-k"},multi[m]),el("span",{cls:"kv-v",sty:{color:v>=0?"var(--income)":"var(--expense)"}},(v>=0?"لك ":"عليك ")+fmt(Math.abs(v)))]));}
    body.appendChild(pc);
  }
  if(done.length){
    var show=!!UI.showSettled;
    body.appendChild(el("button",{cls:"link-btn",sty:{textAlign:"right"},onclick:function(){UI.showSettled=!show;render();}},(show?"▾ ":"▸ ")+"المسدّدة ("+done.length+")"));
    if(show){var dc=el("div",{cls:"card"});for(var q=0;q<done.length;q++)dc.appendChild(debtRow(done[q],q===done.length-1));body.appendChild(dc);}
  }
  page.appendChild(body);
  page.appendChild(el("button",{cls:"btn",sty:{position:"fixed",bottom:"calc(20px + env(safe-area-inset-bottom))",left:"50%",transform:"translateX(-50%)",width:"calc(100% - 32px)",maxWidth:"398px",background:dir==="in"?"var(--income)":"var(--expense)",boxShadow:"0 4px 20px rgba(0,0,0,.18)",zIndex:"50"},
    onclick:function(){UI.debtId=null;go("editDebt");}},dir==="in"?"＋ دين لي عند شخص":"＋ دين علي لشخص"));
  return page;
}
function pageEditDebt(){
  var isEdit=!!UI.debtId,d=isEdit?findDebt(UI.debtId):null;
  if(isEdit&&!d){UI.view="debts";return pageDebts();}
  var dir=isEdit?d.dir:(UI.debtTab||"in");
  var f=d||{name:"",amount:"",date:today(),due:"",note:"",link:false};
  var page=el("div",{sty:{minHeight:"100vh",paddingBottom:"60px"}});
  page.appendChild(hdrBar(isEdit?"تعديل الدين":(dir==="in"?"دين لي عند شخص":"دين علي لشخص"),isEdit?"debtDetail":"debts"));
  var body=el("div",{cls:"content"});
  var curDir=dir,seg=null;
  if(!isEdit){
    seg=el("div",{cls:"seg"});
    var opts=[["in","💚 لي عنده"],["out","❤️ علي له"]];
    for(var i=0;i<opts.length;i++){(function(o){seg.appendChild(el("button",{cls:curDir===o[0]?"on":"",onclick:function(){curDir=o[0];var b=seg.childNodes;for(var j=0;j<b.length;j++)b[j].className=opts[j][0]===curDir?"on":"";linkLbl.textContent=linkText();}},o[1]));})(opts[i]);}
    body.appendChild(seg);
  }
  body.appendChild(secTitle("اسم الشخص"));
  var names={},dl=el("datalist",{id:"debt-names"});
  for(var n=0;n<S.debts.length;n++)names[S.debts[n].name]=1;
  var nk=Object.keys(names);for(var x=0;x<nk.length;x++)dl.appendChild(el("option",{value:nk[x]}));
  var ni=inpEl({value:f.name,placeholder:"مثال: أحمد",list:"debt-names",autocomplete:"off"});
  body.appendChild(ni);body.appendChild(dl);
  body.appendChild(secTitle("المبلغ ("+CUR+")"));
  var amt=amountField(f.amount);body.appendChild(amt.wrap);
  if(!isEdit) UI.focusEl=ni;
  body.appendChild(secTitle("تاريخ الدين"));
  var dt=inpEl({type:"date",value:f.date||today()});body.appendChild(dt);
  body.appendChild(secTitle("تاريخ الاستحقاق (اختياري)"));
  var due=inpEl({type:"date",value:f.due||""});body.appendChild(due);
  body.appendChild(secTitle("ملاحظة (اختياري)"));
  var note=inpEl({value:f.note||"",placeholder:"مثال: لشراء جوال"});body.appendChild(note);
  /* optional link to budget */
  var linkOn=!!f.link;
  function linkText(){return curDir==="in"?"سجّله كمصروف في الميزانية، والسداد كدخل":"سجّله كدخل في الميزانية، والسداد كمصروف";}
  var chk=el("span",{sty:{fontSize:"20px",marginLeft:"10px"}},linkOn?"☑️":"⬜");
  var linkLbl=el("span",null,linkText());
  body.appendChild(el("button",{cls:"card card-p",sty:{display:"flex",alignItems:"center",textAlign:"right",width:"100%",fontSize:"13px",fontWeight:"700",color:"var(--text)"},onclick:function(){linkOn=!linkOn;chk.textContent=linkOn?"☑️":"⬜";}},[chk,el("div",null,[linkLbl,el("div",{sty:{fontSize:"11px",color:"var(--text3)",fontWeight:"600",marginTop:"2px"}},"اختياري — اتركه فارغاً إذا تبغى الديون منفصلة عن الرصيد")])]));
  body.appendChild(el("button",{cls:"btn",sty:{background:curDir==="in"?"var(--income)":"var(--expense)"},onclick:function(){
    var name=ni.value.trim();if(!name){toast("اكتب اسم الشخص");ni.focus();return;}
    var a=parseFloat(amt.inp.value);if(!a||a<=0){toast("أدخل مبلغاً صحيحاً");return;}
    if(isEdit&&a<debtPaid(d)){toast("المبلغ أقل من المسدّد ("+fmt(debtPaid(d))+")");return;}
    var obj=d||{id:uid().slice(1),dir:curDir,pays:[],closed:false};
    obj.name=name;obj.amount=a;obj.date=dt.value||today();obj.due=due.value||"";obj.note=note.value.trim();obj.link=linkOn;
    obj.closed=debtLeft(obj)<=0;if(obj.closed&&!obj.closedAt)obj.closedAt=today();if(!obj.closed)obj.closedAt=null;
    if(!d)S.debts.push(obj);
    syncDebtLinks(obj);save();toast(isEdit?"✓ تم الحفظ":"✓ تمت الإضافة");
    UI.debtTab=obj.dir;
    if(isEdit){go("debtDetail");}else go("debts");
  }},isEdit?"💾 حفظ":"✅ إضافة"));
  page.appendChild(body);return page;
}
function pageDebtDetail(){
  var d=findDebt(UI.debtId);if(!d){UI.view="debts";return pageDebts();}
  var paid=debtPaid(d),left=debtLeft(d),pct=d.amount>0?Math.min(100,paid/d.amount*100):0,col=d.dir==="in"?"var(--income)":"var(--expense)";
  var page=el("div",{sty:{minHeight:"100vh",paddingBottom:"60px"}}),hdr=hdrBar(d.name,"debts");
  hdr.appendChild(el("div",{sty:{marginTop:"14px",textAlign:"center"}},[
    el("div",{sty:{fontSize:"12px",color:"rgba(255,255,255,.75)",fontWeight:"700"}},d.closed?"✅ تم السداد بالكامل":(d.dir==="in"?"💚 المتبقي لك عنده":"❤️ المتبقي عليك له")),
    el("div",{sty:{fontSize:"32px",fontWeight:"900",color:"#fff"}},fmt(d.closed?d.amount:left)+" "+CUR),
    el("div",{cls:"scale-bar-wrap"},[el("div",{cls:"scale-bar-fill",sty:{width:pct+"%",background:"#6EE7B7"}})]),
    el("div",{sty:{fontSize:"11px",color:"rgba(255,255,255,.7)",marginTop:"6px",fontWeight:"700"}},"مسدّد "+fmt(paid)+" من "+fmt(d.amount))
  ]));
  page.appendChild(hdr);
  var body=el("div",{cls:"content"}),info=el("div",{cls:"card"});
  function kv(k,v,c){info.appendChild(el("div",{cls:"kv"},[el("span",{cls:"kv-k"},k),el("span",{cls:"kv-v",sty:c?{color:c}:null},v)]));}
  kv("النوع",d.dir==="in"?"💚 لي عنده":"❤️ علي له");
  kv("تاريخ الدين",dsLbl(d.date)+" "+d.date.slice(0,4));
  if(d.due) kv("الاستحقاق",dsLbl(d.due)+" "+d.due.slice(0,4)+(debtOverdue(d)?" ⚠️ متأخر":""),debtOverdue(d)?"var(--expense)":null);
  if(d.note) kv("ملاحظة",d.note);
  kv("مربوط بالميزانية",d.link?"نعم":"لا");
  body.appendChild(info);
  if(!d.closed){
    body.appendChild(el("div",{cls:"btn-row"},[
      el("button",{cls:"btn",sty:{background:col},onclick:function(){
        askSheet({title:d.dir==="in"?"💵 استلمت دفعة":"💵 دفعت دفعة",sub:"المتبقي: "+fmt(left)+" "+CUR,
          fields:[{type:"number",placeholder:"المبلغ",value:""},{type:"date",value:today()}],okLbl:"تسجيل",
          onOk:function(v,close,err){
            var a=parseFloat(v[0]);if(!a||a<=0){err("أدخل مبلغاً صحيحاً");return;}
            if(a>left+0.0005){err("أكبر من المتبقي ("+fmt(left)+")");return;}
            d.pays=d.pays||[];d.pays.push({id:uid().slice(1),amount:a,date:v[1]||today()});
            if(debtLeft(d)<=0){d.closed=true;d.closedAt=v[1]||today();}
            syncDebtLinks(d);save();close();toast(d.closed?"🎉 تم السداد بالكامل":"✓ تم تسجيل الدفعة");render();
          }});
      }},"💵 تسجيل دفعة"),
      el("button",{cls:"btn btn-ghost",onclick:function(){
        modal("تسوية كاملة؟","سيُسجَّل المتبقي ("+fmt(left)+" "+CUR+") كدفعة أخيرة اليوم.",false,function(){
          d.pays=d.pays||[];d.pays.push({id:uid().slice(1),amount:left,date:today()});d.closed=true;d.closedAt=today();
          syncDebtLinks(d);save();toast("🎉 تم السداد بالكامل");render();
        },"تسوية");
      }},"✅ تسوية كاملة")
    ]));
  }
  if((d.pays||[]).length){
    body.appendChild(secTitle("الدفعات ("+d.pays.length+")"));
    var pc=el("div",{cls:"card"}),ps=d.pays.slice().sort(function(a,b){return a.date<b.date?1:-1;});
    for(var i=0;i<ps.length;i++){
      (function(p,last){
        pc.appendChild(el("div",{cls:"tx-row",sty:{borderBottom:last?"none":"1px solid var(--border)"}},[
          el("div",{cls:"tx-icon",sty:{background:"var(--surface2)"}},"💵"),
          el("div",{cls:"tx-info"},[el("div",{cls:"tx-name"},fmt(p.amount)+" "+CUR),el("div",{cls:"tx-sub"},dsLbl(p.date)+" "+p.date.slice(0,4))]),
          el("button",{sty:{color:"var(--text3)",fontSize:"16px",padding:"6px"},onclick:function(){
            modal("حذف الدفعة؟",fmt(p.amount)+" "+CUR,false,function(){
              unlinkTx(p.txId);d.pays=d.pays.filter(function(x){return x.id!==p.id;});
              if(debtLeft(d)>0){d.closed=false;d.closedAt=null;}
              save();toast("تم الحذف");render();
            });
          }},"🗑️")
        ]));
      })(ps[i],i===ps.length-1);
    }
    body.appendChild(pc);
  }
  body.appendChild(el("div",{cls:"btn-row"},[
    el("button",{cls:"btn btn-ghost",onclick:function(){go("editDebt");}},"✏️ تعديل"),
    el("button",{cls:"btn btn-danger",onclick:function(){
      modal("حذف الدين؟",d.name+" — "+fmt(d.amount)+" "+CUR+(d.link?"\nستُحذف معه المعاملات المرتبطة في الميزانية.":""),true,function(){
        d.link=false;syncDebtLinks(d);S.debts=S.debts.filter(function(x){return x.id!==d.id;});save();toast("تم الحذف");go("debts");
      });
    }},"🗑️ حذف")
  ]));
  page.appendChild(body);return page;
}

/* ═══════════════ REPORT CHARTS ═══════════════ */
var MN_S=["ينا","فبر","مار","أبر","ماي","يون","يول","أغس","سبت","أكت","نوف","ديس"];
function dsLbl(ds){return parseInt(ds.slice(8),10)+" "+MN[parseInt(ds.slice(5,7),10)-1];}
function dStr(d){return d.getFullYear()+"-"+pad2(d.getMonth()+1)+"-"+pad2(d.getDate());}
function periodDays(ym){
  var p=ym.split("-"),d=new Date(parseInt(p[0],10),parseInt(p[1],10)-1,cycDay()),r=[];
  while(periodOf(dStr(d))===ym&&r.length<32){r.push(dStr(d));d.setDate(d.getDate()+1);}
  return r;
}
function prevPeriod(ym,n){var p=ym.split("-"),y=parseInt(p[0],10),m=parseInt(p[1],10)-n;while(m<1){m+=12;y--;}return y+"-"+pad2(m);}
function txMatch(t,catId,inclCommit){return t.type==="expense"&&(!catId||t.catId===catId)&&(inclCommit||!t.isCommit);}
function dailySeries(ym,catId,inclCommit){
  var days=periodDays(ym),idx={},out=[],i;
  for(i=0;i<days.length;i++){idx[days[i]]=i;out.push({key:days[i],lbl:String(parseInt(days[i].slice(8),10)),v:0,n:0});}
  for(i=0;i<S.txs.length;i++){var t=S.txs[i];if(idx[t.date]!=null&&txMatch(t,catId,inclCommit)){out[idx[t.date]].v+=t.amount;out[idx[t.date]].n++;}}
  return out;
}
function monthlySeries(ym,catId,n){
  var out=[],keys={},i;
  for(i=n-1;i>=0;i--){var k=prevPeriod(ym,i);keys[k]=out.length;out.push({key:k,lbl:MN_S[parseInt(k.slice(5),10)-1],v:0,inc:0});}
  for(i=0;i<S.txs.length;i++){
    var t=S.txs[i],j=keys[periodOf(t.date)];if(j==null)continue;
    if(t.type==="income"){if(!catId)out[j].inc+=t.amount;}
    else if(!catId||t.catId===catId) out[j].v+=t.amount;
  }
  return out;
}
function niceMax(v){if(v<=0)return 10;var p=Math.pow(10,Math.floor(Math.log(v)/Math.LN10)),f=v/p;return (f<=1?1:f<=2?2:f<=2.5?2.5:f<=5?5:10)*p;}
function fmtShort(v){return v>=1000?(Math.round(v/100)/10)+"k":(v%1===0?String(v):v.toFixed(1));}
var SVGNS="http://www.w3.org/2000/svg";
function sv_(tag,a,sty){var e=document.createElementNS(SVGNS,tag);for(var k in a)if(a.hasOwnProperty(k))e.setAttribute(k,a[k]);if(sty)for(var s in sty)if(sty.hasOwnProperty(s))e.style[s]=sty[s];return e;}
/* RTL bar chart: first item on the right. o={data,dual,selKey,avg,onPick,labelEvery,hiThresh,todayKey} */
function barChartSVG(o){
  var W=340,H=200,top=10,bot=24,yW=34,x0=4,x1=W-yW,ch=H-top-bot,n=o.data.length;
  var mx=0,i;for(i=0;i<n;i++){mx=Math.max(mx,o.data[i].v,o.dual?o.data[i].inc:0);}
  var ymax=niceMax(mx),slot=(x1-x0)/n,svg=sv_("svg",{viewBox:"0 0 "+W+" "+H,width:"100%",height:H,"class":"chart-svg",direction:"ltr"},{direction:"ltr"});
  function Y(v){return top+ch-(v/ymax)*ch;}
  for(var g=0;g<=2;g++){
    var gv=ymax*g/2,gy=Y(gv);
    svg.appendChild(sv_("line",{x1:x0,x2:x1,y1:gy,y2:gy,"stroke-width":1},{stroke:"var(--border)"}));
    var tx=sv_("text",{x:W-2,y:gy+4,"text-anchor":"end","font-size":10},{fill:"var(--text3)",fontWeight:"700"});tx.textContent=fmtShort(gv);svg.appendChild(tx);
  }
  for(i=0;i<n;i++){
    var d=o.data[i],cx=x1-slot*(i+0.5),sel=d.key===o.selKey,bw;
    if(sel) svg.appendChild(sv_("rect",{x:cx-slot/2,y:top,width:slot,height:ch,rx:4},{fill:"var(--surface2)"}));
    if(o.dual){
      bw=Math.min(12,slot*0.34);
      if(d.inc>0) svg.appendChild(sv_("rect",{x:cx,y:Y(d.inc),width:bw,height:Math.max(1,(d.inc/ymax)*ch),rx:2},{fill:"var(--income)",opacity:sel||!o.selKey?"1":".55"}));
      if(d.v>0) svg.appendChild(sv_("rect",{x:cx-bw,y:Y(d.v),width:bw,height:Math.max(1,(d.v/ymax)*ch),rx:2},{fill:"var(--expense)",opacity:sel||!o.selKey?"1":".55"}));
    } else {
      bw=Math.max(3,Math.min(18,slot*0.68));
      var col=sel?"var(--text)":(o.hiThresh&&d.v>o.hiThresh)?"var(--expense)":"var(--theme-accent)";
      if(d.v>0) svg.appendChild(sv_("rect",{x:cx-bw/2,y:Y(d.v),width:bw,height:Math.max(1.5,(d.v/ymax)*ch),rx:Math.min(3,bw/2)},{fill:col}));
      if(d.key===o.todayKey) svg.appendChild(sv_("circle",{cx:cx,cy:top+ch+4,r:2},{fill:"var(--theme-accent)"}));
    }
    if(i%(o.labelEvery||1)===0||i===n-1){
      var lt=sv_("text",{x:cx,y:H-6,"text-anchor":"middle","font-size":10},{fill:sel?"var(--text)":"var(--text3)",fontWeight:sel?"900":"700"});lt.textContent=d.lbl;svg.appendChild(lt);
    }
    (function(dd){
      var hit=sv_("rect",{x:cx-slot/2,y:0,width:slot,height:H,"class":"hit"},{fill:"transparent",cursor:"pointer"});
      hit.addEventListener("click",function(){o.onPick(dd);});svg.appendChild(hit);
    })(d);
  }
  if(o.avg>0){
    var ay=Y(o.avg);
    svg.appendChild(sv_("line",{x1:x0,x2:x1,y1:ay,y2:ay,"stroke-width":1.5,"stroke-dasharray":"4 3"},{stroke:"var(--amber)",pointerEvents:"none"}));
  }
  return svg;
}
function miniStat(l,v,c,sub){return el("div",{cls:"stat-card"},[el("div",{cls:"stat-lbl"},l),el("div",{cls:"stat-val",sty:{color:c||"var(--text)",fontSize:"14px"}},v),sub?el("div",{cls:"stat-cur"},sub):null]);}
function pctChange(a,b){if(!(b>0))return null;return Math.round((a-b)/b*100);}

function reportChart(ym){
  var wrap=el("div",{cls:"card card-p"}),mode=UI.repMode||"daily",catId=UI.repCat||null;
  /* mode toggle */
  var seg=el("div",{cls:"seg"});
  var modes=[["daily","📅 يومي"],["monthly","🗓️ شهري"]];
  for(var i=0;i<modes.length;i++){(function(m){seg.appendChild(el("button",{cls:mode===m[0]?"on":"",onclick:function(){UI.repMode=m[0];UI.repDay=null;render();}},m[1]));})(modes[i]);}
  wrap.appendChild(seg);
  /* category filter: categories with spend in the last 12 periods */
  var used={},from=prevPeriod(ym,11);
  for(i=0;i<S.txs.length;i++){var t=S.txs[i],pk=periodOf(t.date);if(t.type==="expense"&&pk>=from&&pk<=ym)used[t.catId]=1;}
  var chips=el("div",{cls:"chip-scroll"});
  chips.appendChild(el("button",{cls:"cat-chip"+(!catId?" chip-on":""),onclick:function(){UI.repCat=null;UI.repDay=null;render();}},"الكل"));
  for(i=0;i<EXP_CATS.length;i++){
    (function(c){if(!used[c.id])return;
      chips.appendChild(el("button",{cls:"cat-chip"+(catId===c.id?" chip-on":""),sty:catId===c.id?{borderColor:c.c,background:c.c+"22"}:null,onclick:function(){UI.repCat=c.id;UI.repDay=null;render();}},c.em+" "+c.lbl));
    })(EXP_CATS[i]);
  }
  wrap.appendChild(chips);
  var catLbl=catId?getCat("expense",catId).lbl:"";

  if(mode==="daily"){
    var incl=!!UI.repInclCommit,data=dailySeries(ym,catId,incl),td=today(),isCur=ym===thisMonth();
    var elapsed=0,sum=0,zero=0,hi=null;
    for(i=0;i<data.length;i++){
      if(isCur&&data[i].key>td)break;
      elapsed++;sum+=data[i].v;if(!data[i].v)zero++;
      if(!hi||data[i].v>hi.v)hi=data[i];
    }
    var avg=elapsed?sum/elapsed:0;
    wrap.appendChild(el("div",{cls:"chart-cap"},"الصرف اليومي"+(catLbl?" · "+catLbl:"")+" — "+monthLbl(ym)));
    wrap.appendChild(el("div",{cls:"chart-legend-row"},[el("span",null,[el("i",{sty:{background:"var(--theme-accent)"}}),"عادي"]),el("span",null,[el("i",{sty:{background:"var(--expense)"}}),"أعلى من المتوسط بكثير"]),el("span",null,[el("i",{sty:{background:"var(--amber)",height:"2px"}}),"المتوسط"])]));
    wrap.appendChild(barChartSVG({data:data,selKey:UI.repDay,avg:avg,hiThresh:avg*1.5,todayKey:isCur?td:null,labelEvery:5,
      onPick:function(d){UI.repDay=UI.repDay===d.key?null:d.key;render();}}));
    wrap.appendChild(el("button",{cls:"link-btn",sty:{fontSize:"12px",padding:"4px 0"},onclick:function(){UI.repInclCommit=!incl;render();}},
      incl?"☑︎ يشمل الالتزامات الثابتة":"☐ بدون الالتزامات الثابتة (اضغط لإظهارها)"));
    var sr=el("div",{cls:"stats-row",sty:{marginTop:"8px"}});
    sr.appendChild(miniStat("متوسط يومي",fmt(avg),"var(--amber)",CUR));
    sr.appendChild(miniStat("أعلى يوم",hi&&hi.v?fmt(hi.v):"—","var(--expense)",hi&&hi.v?dsLbl(hi.key):""));
    sr.appendChild(miniStat("أيام بلا صرف",String(zero),"var(--income)","من "+elapsed));
    wrap.appendChild(sr);
    /* selected day detail */
    if(UI.repDay){
      var dtx=S.txs.filter(function(t){return t.date===UI.repDay&&txMatch(t,catId,incl);}),dsum=0;
      for(i=0;i<dtx.length;i++)dsum+=dtx[i].amount;
      wrap.appendChild(el("div",{cls:"sel-head"},[el("span",null,"📍 "+dsLbl(UI.repDay)),el("span",{sty:{color:"var(--expense)"}},fmt(dsum)+" "+CUR)]));
      var lc=el("div",{cls:"sel-list"});
      if(!dtx.length) lc.appendChild(el("div",{sty:{padding:"10px",textAlign:"center",color:"var(--text3)",fontSize:"13px"}},"لا يوجد صرف في هذا اليوم 👍"));
      for(i=0;i<dtx.length;i++) lc.appendChild(txRow(dtx[i],i===dtx.length-1));
      wrap.appendChild(lc);
    } else wrap.appendChild(el("div",{cls:"chart-hint"},"اضغط على أي يوم لعرض مصاريفه"));
  } else {
    var md=monthlySeries(ym,catId,12),cnt=0,tot=0,hm=null;
    for(i=0;i<md.length;i++){if(md[i].v>0||md[i].inc>0){cnt++;tot+=md[i].v;}if(!hm||md[i].v>hm.v)hm=md[i];}
    var mAvg=cnt?tot/cnt:0,cur=md[md.length-1],prev=md[md.length-2],ch=pctChange(cur.v,prev.v);
    wrap.appendChild(el("div",{cls:"chart-cap"},(catLbl?"مصروفات «"+catLbl+"»":"الدخل والمصروفات")+" — آخر 12 شهراً"));
    if(!catId) wrap.appendChild(el("div",{cls:"chart-legend-row"},[el("span",null,[el("i",{sty:{background:"var(--income)"}}),"دخل"]),el("span",null,[el("i",{sty:{background:"var(--expense)"}}),"مصروفات"]),el("span",null,[el("i",{sty:{background:"var(--amber)",height:"2px"}}),"متوسط الصرف"])]));
    wrap.appendChild(barChartSVG({data:md,dual:!catId,selKey:ym,avg:mAvg,hiThresh:catId?mAvg*1.3:0,labelEvery:1,
      onPick:function(d){UI.month=d.key;render();}}));
    var sr2=el("div",{cls:"stats-row",sty:{marginTop:"8px"}});
    sr2.appendChild(miniStat("متوسط شهري",fmt(mAvg),"var(--amber)",CUR));
    sr2.appendChild(miniStat("أعلى شهر",hm&&hm.v?fmt(hm.v):"—","var(--expense)",hm&&hm.v?monthLbl(hm.key):""));
    sr2.appendChild(miniStat("مقارنة بالسابق",ch==null?"—":(ch>0?"▲ ":ch<0?"▼ ":"")+Math.abs(ch)+"%",ch==null?null:ch>0?"var(--expense)":"var(--income)",monthLbl(ym)));
    wrap.appendChild(sr2);
    wrap.appendChild(el("div",{cls:"chart-hint"},"اضغط على أي شهر لعرض تفاصيله"));
  }
  return wrap;
}

function pageReport(){
  UI.tab="report";
  var ym=UI.month,st=monthStats(ym),year=ym.slice(0,4),allM=dataMonths(),yearMs=[],yInc=0,yExp=0;
  for(var i=0;i<allM.length;i++) if(allM[i].indexOf(year)===0) yearMs.push(allM[i]);
  for(var j=0;j<yearMs.length;j++){var ys=monthStats(yearMs[j]);yInc+=ys.inc;yExp+=ys.exp;}
  var page=el("div",{cls:"page"}),hdr=el("div",{cls:"hdr"});
  hdr.appendChild(el("div",{sty:{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"16px"}},[
    el("div",null,[el("div",{cls:"hdr-title"},"التقارير المالية"),el("div",{sty:{fontSize:"24px",fontWeight:"900",color:"#fff"}},year)]),
    el("div",{sty:{textAlign:"left"}},[el("div",{sty:{fontSize:"11px",color:"rgba(255,255,255,.65)",fontWeight:"700"}},"الرصيد السنوي"),el("div",{sty:{fontSize:"20px",fontWeight:"900",color:(yInc-yExp)>=0?"#6EE7B7":"#FCA5A5"}},fmt(yInc-yExp)+" "+CUR)])
  ]));
  hdr.appendChild(monthScroller(ym,function(m){UI.month=m;go("report");}));
  page.appendChild(hdr);
  var body=el("div",{cls:"content"});
  body.appendChild(secTitle("مستوى الصرف"));
  body.appendChild(reportChart(ym));
  body.appendChild(secTitle("ملخص "+year));
  var ar=el("div",{cls:"stats-row"}),sts=[{l:"الدخل",v:yInc,c:"var(--income)"},{l:"المصروفات",v:yExp,c:"var(--expense)"},{l:"الرصيد",v:yInc-yExp,c:(yInc-yExp)>=0?"var(--income)":"var(--expense)"}];
  for(var k=0;k<sts.length;k++) ar.appendChild(el("div",{cls:"stat-card"},[el("div",{cls:"stat-lbl"},sts[k].l),el("div",{cls:"stat-val",sty:{color:sts[k].c,fontSize:"15px"}},fmt(Math.abs(sts[k].v))),el("div",{cls:"stat-cur"},CUR)]));
  body.appendChild(ar);

  body.appendChild(secTitle("الجدول الشهري"));
  var tbl=el("table"),hr=el("tr"),ths=["الشهر","دخل","مصروفات","رصيد"];
  for(var h=0;h<ths.length;h++) hr.appendChild(el("th",null,ths[h]));
  tbl.appendChild(el("thead",null,[hr]));
  var tb=el("tbody");
  for(var r=0;r<yearMs.length;r++){
    var ms=monthStats(yearMs[r]),b2=ms.inc-ms.exp;
    if(!ms.txs.length)continue;
    tb.appendChild(el("tr",null,[el("td",{sty:{fontWeight:"700"}},monthLbl(yearMs[r])),el("td",{cls:"td-inc"},fmt(ms.inc)),el("td",{cls:"td-exp"},fmt(ms.exp)),el("td",{cls:"td-bal",sty:{color:b2>=0?"var(--income)":"var(--expense)"}},fmt(b2))]));
  }
  tb.appendChild(el("tr",{sty:{background:"var(--surface2)"}},[el("td",{sty:{fontWeight:"900"}},"المجموع"),el("td",{cls:"td-inc"},fmt(yInc)),el("td",{cls:"td-exp"},fmt(yExp)),el("td",{cls:"td-bal",sty:{color:(yInc-yExp)>=0?"var(--income)":"var(--expense)"}},fmt(yInc-yExp))]));
  tbl.appendChild(tb);body.appendChild(el("div",{cls:"card tbl-wrap"},[tbl]));

  body.appendChild(secTitle("تفاصيل "+monthLbl(ym)));
  var g=el("div",{cls:"grid2"}),md=[{l:"الدخل",v:st.inc,c:"var(--income)"},{l:"المتاح للإنفاق",v:st.available,c:"var(--accent)"},{l:"الالتزامات",v:st.commitExp,c:"var(--commit)"},{l:"المصاريف العادية",v:st.freeExp,c:"var(--expense)"}];
  for(var x=0;x<md.length;x++) g.appendChild(el("div",{cls:"stat-card"},[el("div",{cls:"stat-lbl"},md[x].l),el("div",{cls:"stat-val",sty:{color:md[x].c,fontSize:"15px"}},fmt(Math.abs(md[x].v))),el("div",{cls:"stat-cur"},CUR)]));
  body.appendChild(g);

  var expData=[];
  for(var y=0;y<EXP_CATS.length;y++){var v=st.byEC[EXP_CATS[y].id]||0;if(v>0)expData.push({cat:EXP_CATS[y],v:v});}
  expData.sort(function(a,b){return b.v-a.v;});
  if(expData.length){
    body.appendChild(secTitle("المصروفات حسب الفئة"));
    var bcEl=el("div",{cls:"bar-chart"});
    for(var z=0;z<expData.length;z++){
      (function(d){
        bcEl.appendChild(el("div",{cls:"bar-row",sty:{cursor:"pointer"},onclick:function(){UI.selectedCat=d.cat;go("catDetail");}},[
          el("div",{cls:"bar-row-lbl"},d.cat.em+" "+d.cat.lbl),
          el("div",{cls:"bar-track"},[el("div",{cls:"bar-fill",sty:{width:(st.exp>0?d.v/st.exp*100:0)+"%",background:d.cat.c}})]),
          el("div",{cls:"bar-val"},fmt(d.v)+" ›")
        ]));
      })(expData[z]);
    }
    body.appendChild(el("div",{cls:"card card-p"},[bcEl]));
  }
  body.appendChild(el("button",{cls:"btn btn-accent",onclick:function(){
    var t="📊 تقرير "+monthLbl(ym)+"\n═══════════════\n💰 الدخل: "+fmt(st.inc)+" "+CUR+"\n📋 الالتزامات: "+fmt(st.commitExp)+" "+CUR+"\n✅ المتاح: "+fmt(st.available)+" "+CUR+"\n💸 المصروفات: "+fmt(st.freeExp)+" "+CUR+"\n"+(st.bal>=0?"✅":"⚠️")+" الرصيد: "+fmt(st.bal)+" "+CUR+"\n";
    for(var i=0;i<expData.length;i++) t+="• "+expData[i].cat.em+" "+expData[i].cat.lbl+": "+fmt(expData[i].v)+" "+CUR+"\n";
    if(navigator.share) navigator.share({title:"تقرير الميزانية",text:t}).catch(function(){});
    else if(navigator.clipboard) navigator.clipboard.writeText(t).then(function(){toast("✓ تم النسخ");});
  }},"📤 مشاركة التقرير"));
  page.appendChild(body);page.appendChild(tabBar());
  return page;
}
function pageCatDetail(){
  var cat=UI.selectedCat;if(!cat){UI.view="report";return pageReport();}
  var ym=UI.month,st=monthStats(ym),txs=st.txs.filter(function(t){return t.type==="expense"&&t.catId===cat.id;}).sort(function(a,b){return a.date<b.date?1:-1;});
  var total=0;for(var i=0;i<txs.length;i++)total+=txs[i].amount;
  var pct=st.exp>0?Math.round(total/st.exp*100):0;
  var page=el("div",{cls:"page"}),hdr=el("div",{cls:"hdr",sty:{background:"linear-gradient(145deg,"+cat.c+","+darken(cat.c,0.8)+")"}});
  hdr.appendChild(el("div",{sty:{display:"flex",alignItems:"center",marginBottom:"16px"}},[backBtn("report"),el("div",{sty:{fontSize:"22px",marginLeft:"10px"}},cat.em),el("div",null,[el("div",{sty:{fontSize:"19px",fontWeight:"900",color:"#fff"}},cat.lbl),el("div",{sty:{fontSize:"12px",color:"rgba(255,255,255,.75)"}},monthLbl(ym))])]));
  var sr=el("div",{cls:"stats-row"});
  function hs(l,v){return el("div",{sty:{background:"rgba(255,255,255,.14)",borderRadius:"12px",padding:"10px 12px"}},[el("div",{sty:{fontSize:"10px",color:"rgba(255,255,255,.7)",fontWeight:"700"}},l),el("div",{sty:{fontSize:"16px",fontWeight:"900",color:"#fff"}},v)]);}
  sr.appendChild(hs("الإجمالي",fmt(total)));sr.appendChild(hs("المعاملات",String(txs.length)));
  if(cat.cap>0) sr.appendChild(hs("من الحد ("+fmt(cat.cap)+")",Math.round(total/cat.cap*100)+"%"));
  else sr.appendChild(hs("من المصروفات",pct+"%"));
  hdr.appendChild(sr);page.appendChild(hdr);
  var body=el("div",{cls:"content"});
  if(!txs.length) body.appendChild(el("div",{cls:"empty"},[el("div",{cls:"empty-icon"},cat.em),el("div",{cls:"empty-title"},"لا توجد معاملات")]));
  else{var card=el("div",{cls:"card"});for(var j=0;j<txs.length;j++)card.appendChild(txRow(txs[j],j===txs.length-1));body.appendChild(card);}
  page.appendChild(body);page.appendChild(tabBar());
  return page;
}

/* ═══════════════ PAGE: MORE ═══════════════ */
function listBtn(icon,t,s,fn,color){
  return el("button",{cls:"list-btn",onclick:fn},[el("div",{cls:"list-ico"},icon),el("div",{cls:"list-txt"},[el("div",{cls:"list-t",sty:color?{color:color}:null},t),s?el("div",{cls:"list-s"},s):null]),el("span",{cls:"list-arrow"},"›")]);
}
function pageMore(){
  UI.tab="more";
  var page=el("div",{cls:"page"}),hdr=el("div",{cls:"hdr"});
  hdr.appendChild(el("div",{sty:{fontSize:"22px",fontWeight:"900",color:"#fff"}},"المزيد"));
  hdr.appendChild(el("div",{sty:{fontSize:"13px",color:"rgba(255,255,255,.7)"}},"الحساب والأمان والإعدادات"));
  page.appendChild(hdr);
  var body=el("div",{cls:"content"});

  /* Account */
  if(!LOCAL_MODE){
  body.appendChild(secTitle("الاشتراك"));
  var acc=el("div",{cls:"card"});
  acc.appendChild(el("div",{cls:"kv"},[el("span",{cls:"kv-k"},"الحساب"),el("span",{cls:"kv-v",sty:{direction:"ltr"}},USER?USER.email:"")]));
  if(LIC){
    var dl=daysLeft(LIC.expiresAt);
    acc.appendChild(el("div",{cls:"kv"},[el("span",{cls:"kv-k"},"النوع"),el("span",{cls:"kv-v"},LIC.trial?"🎁 فترة تجريبية":"✅ اشتراك مدفوع")]));
    acc.appendChild(el("div",{cls:"kv"},[el("span",{cls:"kv-k"},"ينتهي في"),el("span",{cls:"kv-v",sty:{color:dl<=14?"var(--expense)":null}},dateLbl(LIC.expiresAt)+" ("+daysW(dl)+")")]));
    acc.appendChild(el("div",{cls:"kv"},[el("span",{cls:"kv-k"},"الأجهزة"),el("span",{cls:"kv-v"},(LIC.devCount||1)+" من "+(LIC.maxDevices||1))]));
    if(LIC.offline) acc.appendChild(el("div",{cls:"kv"},[el("span",{cls:"kv-k"},"الحالة"),el("span",{cls:"kv-v"},"📡 بدون اتصال")]));
  }
  var isTrial=LIC&&LIC.trial;
  acc.appendChild(listBtn(isTrial?"🛒":"🔄",isTrial?"الاشتراك الكامل":"تجديد الاشتراك","تواصل عبر واتساب",function(){openWA("السلام عليكم، أرغب "+(isTrial?"بالاشتراك في":"بتجديد اشتراك")+" ميزانية البيت\nالحساب: "+(USER?USER.email:""));}));
  acc.appendChild(listBtn("🔑","تغيير كلمة المرور","نرسل رابطاً إلى بريدك",function(){
    firebase.auth().sendPasswordResetEmail(USER.email).then(function(){toast("✓ أُرسل الرابط إلى بريدك");},function(){toast("تعذّر الإرسال — تحقق من الاتصال");});
  }));
  body.appendChild(acc);
  }

  /* Security */
  body.appendChild(secTitle("الأمان والخصوصية"));
  var sec=el("div",{cls:"card"}),pinOn=VAULT&&VAULT.mode==="pin";
  if(pinOn){
    sec.appendChild(listBtn("🔒","قفل الرمز: مفعّل","يُقفل تلقائياً بعد دقيقة في الخلفية",lockNow));
    sec.appendChild(listBtn("🔢","تغيير الرمز","",changePinFlow));
    sec.appendChild(listBtn("🔓","إيقاف القفل","",disablePin));
  } else {
    sec.appendChild(listBtn("🔓","قفل الرمز: غير مفعّل","فعّله لحماية بياناتك بتشفير مرتبط برمزك",enablePinFlow));
  }
  sec.appendChild(listBtn("🛡️","سياسة الخصوصية","ماذا نحفظ وماذا لا نحفظ",showPrivacy));
  body.appendChild(sec);

  /* Appearance */
  body.appendChild(secTitle("المظهر"));
  var ac=el("div",{cls:"card card-p"}),aw=el("div",{cls:"wrap-grid"});
  var seg=el("div",{cls:"seg",sty:{marginBottom:"14px"}}),modes=[["auto","🌗 تلقائي"],["light","☀️ فاتح"],["dark","🌙 داكن"]],cur=themePref();
  for(var mi=0;mi<modes.length;mi++){
    (function(m){seg.appendChild(el("button",{cls:cur===m[0]?"on":"",onclick:function(){sv("mb2_theme",m[0]);applyTheme();render();}},m[1]));})(modes[mi]);
  }
  ac.appendChild(seg);
  for(var i=0;i<ACCENTS.length;i++){
    (function(c){aw.appendChild(el("button",{sty:{width:"36px",height:"36px",borderRadius:"10px",background:c,border:(S.accent===c?"3px solid var(--text)":"3px solid transparent")},onclick:function(){S.accent=c;applyAccent(c);save();render();}}));})(ACCENTS[i]);
  }
  var picker=el("input",{type:"color",value:S.accent||"#1D6FA4",sty:{width:"36px",height:"36px",border:"none",borderRadius:"10px",padding:"0",background:"none"}});
  picker.addEventListener("change",function(){S.accent=picker.value;applyAccent(picker.value);save();render();});
  aw.appendChild(picker);ac.appendChild(aw);body.appendChild(ac);

  /* Commitments + categories */
  body.appendChild(secTitle("الإعدادات"));
  var st=el("div",{cls:"card"});
  st.appendChild(listBtn("💱","العملة",S.currency.code+" · "+S.currency.lbl,pickCurrency));
  st.appendChild(listBtn("📅","بداية الشهر المالي",cycDay()===1?"يوم 1 (الشهر الميلادي)":"يوم "+cycDay()+" من كل شهر (يوم الراتب)",pickCycleDay));
  var dtt=debtTotals();
  st.appendChild(listBtn("🤝","الديون",dtt.open?("لك "+fmt(dtt.inn)+" · عليك "+fmt(dtt.out)):"لي عند الناس وعلي للناس",function(){go("debts");}));
  st.appendChild(listBtn("📋","الالتزامات الثابتة",S.commits.length+" التزام · "+fmt(totalCommits())+" "+CUR+"/شهر",function(){go("commitments");}));
  st.appendChild(listBtn("🏷️","فئات المصروفات وحدودها",EXP_CATS.length+" فئة · "+EXP_CATS.filter(function(c){return c.cap>0;}).length+" بحد شهري",function(){UI.editCatType="expense";go("catList");}));
  st.appendChild(listBtn("🏷️","فئات الدخل",INC_CATS.length+" فئة",function(){UI.editCatType="income";go("catList");}));
  body.appendChild(st);

  /* Data */
  body.appendChild(secTitle("البيانات"));
  var dc=el("div",{cls:"card"});
  dc.appendChild(listBtn("📤","نسخة احتياطية مشفّرة",S.lastBackup?("آخر نسخة: "+dateLbl(S.lastBackup)):"لم تأخذ نسخة بعد",exportBackup));
  dc.appendChild(listBtn("📥","استرجاع نسخة احتياطية","ملف JSON",function(){pickFile(".json",importBackup);}));
  dc.appendChild(listBtn("📊","استيراد Excel","ملف الميزانية القديم",function(){pickFile(".xlsx,.xls",handleXL);}));
  body.appendChild(dc);

  body.appendChild(secTitle("منطقة الخطر"));
  var dz=el("div",{cls:"card"});
  dz.appendChild(listBtn("🗑️","مسح كل المعاملات","يبقى الاشتراك والفئات",function(){
    modal("مسح كل المعاملات والالتزامات؟","ننصح بأخذ نسخة احتياطية أولاً.",true,function(){S.txs=[];S.commits=[];save();toast("✓ تم المسح");render();},"مسح");
  },"var(--expense)"));
  if(!LOCAL_MODE) dz.appendChild(listBtn("🚪","تسجيل الخروج","تبقى بياناتك مشفّرة على هذا الجهاز",function(){
    modal("تسجيل الخروج؟","بياناتك تبقى مشفّرة في هذا الجهاز وتعود عند الدخول بنفس الحساب.",false,function(){firebase.auth().signOut();},"خروج");
  }));
  body.appendChild(dz);
  body.appendChild(el("div",{cls:"brand-foot",sty:{textAlign:"center"}},"\u200Fميزانية البيت v"+APP_VERSION+" — © سُحُب · LSY — جميع الحقوق محفوظة"));
  page.appendChild(body);page.appendChild(tabBar());
  return page;
}
function showPrivacy(){
  infoSheet("🛡️ سياسة الخصوصية",
    (LOCAL_MODE?"لا نحفظ أي شيء على خوادمنا.\n\n":"ما نحفظه على خوادمنا:\n• بريدك الإلكتروني (لتسجيل الدخول)\n• تاريخ انتهاء الاشتراك وعدد الأجهزة\n\n")+
    "ما لا نحفظه أبداً:\n• أي مبلغ أو معاملة أو التزام أو فئة\n• أي تقرير أو رصيد\n\n"+
    "بياناتك المالية مشفّرة بمعيار AES-256 داخل جهازك فقط، ولا تغادره إلا إذا أخذت أنت نسخة احتياطية.\n\n"+
    "عند تفعيل قفل الرمز يصبح مفتاح التشفير مرتبطاً برمزك، فلا يستطيع أحد — ولا نحن — فتح البيانات بدونه.\n\n"+
    "لحذف حسابك أو الاستفسار تواصل معنا عبر واتساب.");
}

/* ═══════════════ CATEGORIES ═══════════════ */
function pageCatList(){
  var type=UI.editCatType,cats=type==="income"?INC_CATS:EXP_CATS;
  var page=el("div",{sty:{minHeight:"100vh",paddingBottom:"40px"}});
  page.appendChild(hdrBar(type==="income"?"فئات الدخل":"فئات المصروفات","more"));
  var body=el("div",{cls:"content"}),card=el("div",{cls:"card"});
  if(type==="expense") body.appendChild(banner("info","💡 اضغط على أي فئة لتحديد حد شهري لها"));
  for(var i=0;i<cats.length;i++){(function(c){card.appendChild(listBtn(c.em,c.lbl,c.cap>0?"الحد الشهري: "+fmt(c.cap)+" "+CUR:"",function(){UI.editCat=Object.assign({},c);go("editCat");}));})(cats[i]);}
  card.appendChild(listBtn("＋",type==="income"?"إضافة فئة دخل":"إضافة فئة مصروف","",function(){UI.editCat=null;go("editCat");},"var(--accent)"));
  body.appendChild(card);page.appendChild(body);return page;
}
function pageEditCat(){
  var isEdit=!!UI.editCat,type=UI.editCatType,f=isEdit?UI.editCat:{id:"",lbl:"",em:"😊",c:CAT_COLORS[0]};
  var curColor=f.c||CAT_COLORS[0],curEmoji=f.em||"😊";
  var page=el("div",{sty:{minHeight:"100vh",paddingBottom:"60px"}});
  page.appendChild(hdrBar(isEdit?"تعديل الفئة":"فئة جديدة","catList"));
  var body=el("div",{cls:"content"});
  var pIcon=el("div",{sty:{width:"48px",height:"48px",borderRadius:"14px",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"24px",background:curColor+"22",marginLeft:"12px"}},curEmoji);
  var pLbl=el("div",{sty:{flex:"1",fontSize:"16px",fontWeight:"800"}},f.lbl||"اسم الفئة");
  body.appendChild(el("div",{cls:"card card-p",sty:{display:"flex",alignItems:"center"}},[pIcon,pLbl]));
  body.appendChild(secTitle("اسم الفئة"));
  var ni=inpEl({value:f.lbl||"",placeholder:"مثال: تأمين، رياضة، قهوة"});
  ni.addEventListener("input",function(){pLbl.textContent=ni.value||"اسم الفئة";});body.appendChild(ni);
  body.appendChild(secTitle("الأيقونة"));
  var ew=el("div",{cls:"wrap-grid"});
  function paintE(){var b=ew.querySelectorAll("button");for(var i=0;i<b.length;i++){var on=b[i].textContent===curEmoji;b[i].style.borderColor=on?"var(--accent)":"var(--border)";b[i].style.background=on?"var(--accent-bg)":"var(--surface2)";}}
  for(var i=0;i<CAT_EMOJIS.length;i++){(function(em){ew.appendChild(el("button",{sty:{width:"42px",height:"42px",borderRadius:"10px",border:"2px solid var(--border)",fontSize:"20px"},onclick:function(){curEmoji=em;pIcon.textContent=em;paintE();}},em));})(CAT_EMOJIS[i]);}
  body.appendChild(ew);paintE();
  body.appendChild(secTitle("اللون"));
  var cw=el("div",{cls:"wrap-grid"});
  function paintC(){var b=cw.querySelectorAll("button");for(var i=0;i<b.length;i++)b[i].style.border=(CAT_COLORS[i]===curColor?"3px solid var(--text)":"3px solid transparent");}
  for(var j=0;j<CAT_COLORS.length;j++){(function(c){cw.appendChild(el("button",{sty:{width:"36px",height:"36px",borderRadius:"10px",background:c},onclick:function(){curColor=c;pIcon.style.background=c+"22";paintC();}}));})(CAT_COLORS[j]);}
  body.appendChild(cw);paintC();
  var capInp=null;
  if(type==="expense"){
    body.appendChild(secTitle("الحد الشهري (اختياري)"));
    capInp=amountField(f.cap>0?f.cap:"");capInp.inp.setAttribute("placeholder","بدون حد");capInp.inp.className="inp";
    body.appendChild(capInp.wrap);
    body.appendChild(el("div",{sty:{fontSize:"11px",color:"var(--text3)",marginTop:"6px"}},"تنبيه عند 80% وعند التجاوز. اتركه فارغاً لإلغاء الحد."));
  }
  var row=el("div",{cls:"btn-row"});
  row.appendChild(el("button",{cls:"btn btn-accent",onclick:function(){
    var name=ni.value.trim();if(!name){toast("أدخل اسم الفئة");return;}
    var cats=type==="income"?INC_CATS:EXP_CATS,cap=capInp?(parseFloat(capInp.inp.value)||0):0;
    var upd={lbl:name,em:curEmoji,c:curColor};if(type==="expense")upd.cap=cap>0?cap:0;
    if(isEdit){for(var i=0;i<cats.length;i++)if(cats[i].id===f.id){cats[i]=Object.assign({},cats[i],upd);break;}}
    else{upd.id="cat_"+Date.now();cats.push(upd);}
    save();toast(isEdit?"✓ تم الحفظ":"✓ تمت الإضافة");go("catList");
  }},isEdit?"💾 حفظ":"✅ إضافة"));
  if(isEdit){
    row.appendChild(el("button",{cls:"btn btn-danger",sty:{width:"auto",padding:"14px 18px"},onclick:function(){
      var cats=type==="income"?INC_CATS:EXP_CATS;
      if(cats.length<=1){toast("لا يمكن حذف آخر فئة");return;}
      modal("حذف الفئة؟",f.lbl+"\nالمعاملات المرتبطة بها ستظهر تحت «أخرى».",false,function(){
        var nc=cats.filter(function(c){return c.id!==f.id;});
        if(type==="income"){INC_CATS=nc;}else{EXP_CATS=nc;}
        save();toast("تم الحذف");go("catList");
      });
    }},"🗑️"));
  }
  body.appendChild(row);page.appendChild(body);return page;
}

/* ═══════════════ BACKUP (encrypted) ═══════════════ */
function pickFile(accept,handler){var i=document.createElement("input");i.type="file";i.accept=accept;i.onchange=handler;i.click();}
function downloadText(name,text){
  var a=document.createElement("a");a.href=URL.createObjectURL(new Blob([text],{type:"application/json"}));a.download=name;
  document.body.appendChild(a);a.click();setTimeout(function(){URL.revokeObjectURL(a.href);a.parentNode.removeChild(a);},1500);
}
function exportBackup(){
  askSheet({title:"📤 نسخة احتياطية مشفّرة",sub:"اختر كلمة سر للملف. ستحتاجها لاسترجاعه — لا يمكن فتحه بدونها.",
    fields:[{type:"password",placeholder:"كلمة سر الملف (6 أحرف على الأقل)"},{type:"password",placeholder:"أعد كتابتها"}],okLbl:"تنزيل الملف",
    onOk:function(v,close,err){
      if(v[0].length<6){err("6 أحرف على الأقل");return;}
      if(v[0]!==v[1]){err("كلمتا السر غير متطابقتين");return;}
      var payload={txs:S.txs,commits:S.commits,debts:S.debts,expCats:EXP_CATS,incCats:INC_CATS};
      wrapWith(v[0],enc.encode(JSON.stringify(payload))).then(function(w){
        downloadText("ميزانية-البيت-"+today()+".json",JSON.stringify({_t:"mb3",v:3,d:today(),salt:w.salt,iv:w.iv,ct:w.ct}));
        S.lastBackup=Date.now();save();close();toast("✓ تم حفظ النسخة");render();
      },function(){err("حدث خطأ");});
    }});
}
function applyBackup(p){
  modal("استبدال البيانات الحالية؟","سيتم استبدال كل المعاملات والالتزامات والفئات بمحتوى النسخة.",true,function(){
    S.txs=p.txs||[];S.commits=p.commits||[];S.debts=p.debts||[];
    if(p.expCats&&p.expCats.length)EXP_CATS=p.expCats;
    if(p.incCats&&p.incCats.length)INC_CATS=p.incCats;
    S.lastBackup=Date.now();save();toast("✓ تم الاسترجاع");go("home");
  },"استبدال");
}
function importBackup(e){
  var file=e.target.files[0];if(!file)return;
  var r=new FileReader();
  r.onload=function(ev){
    var d;try{d=JSON.parse(ev.target.result);}catch(x){toast("الملف غير صالح");return;}
    if(d&&d._t==="mb3"){
      askSheet({title:"📥 كلمة سر النسخة",fields:[{type:"password",placeholder:"كلمة سر الملف"}],okLbl:"فتح",
        onOk:function(v,close,err){
          unwrapWith(v[0],d).then(function(pt){close();applyBackup(JSON.parse(dec.decode(pt)));},function(){err("كلمة السر غير صحيحة");});
        }});
    } else if(d&&d._t==="mb2"){ applyBackup({txs:d.txs,commits:d.commits,expCats:normCats(d.expCats),incCats:d.incCats}); }
    else toast("الملف غير صالح");
  };
  r.readAsText(file);
}

/* ═══════════════ EXCEL IMPORT ═══════════════ */
var MNS_EN=["jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec"];
function isMonthH(h){var l=String(h||"").toLowerCase().trim();for(var i=0;i<12;i++){if(l.indexOf(MNS_EN[i])===0||l.indexOf(MN[i])>=0)return true;}return false;}
function monthIdx(h){var l=String(h||"").toLowerCase().trim();for(var i=0;i<12;i++){if(l.indexOf(MNS_EN[i])===0||l.indexOf(MN[i])>=0)return i+1;}return -1;}
function handleXL(e){
  var file=e.target.files[0];if(!file)return;
  if(typeof XLSX==="undefined"){toast("مكتبة Excel لم تُحمّل بعد");return;}
  var r=new FileReader();
  r.onload=function(ev){
    try{
      var wb=XLSX.read(new Uint8Array(ev.target.result),{type:"array",cellDates:true}),best=null,hi=-1;
      for(var s=0;s<wb.SheetNames.length&&!best;s++){
        var sh=wb.Sheets[wb.SheetNames[s]];if(!sh||!sh["!ref"])continue;
        var raw=XLSX.utils.sheet_to_json(sh,{header:1,defval:""});
        for(var ri=0;ri<raw.length;ri++){var cnt=0;for(var ci=0;ci<raw[ri].length;ci++)if(isMonthH(raw[ri][ci]))cnt++;if(cnt>=2){best=raw;hi=ri;break;}}
      }
      if(!best){toast("لم يُعثر على بيانات بتنسيق شهري");return;}
      UI.pivotData=parsePivot(best,hi);go("confirmXL");
    }catch(err){toast("خطأ في قراءة الملف");}
  };
  r.readAsArrayBuffer(file);
}
function parsePivot(raw,hIdx){
  var sections=[],ri,ci,si;
  for(ri=hIdx;ri<raw.length;ri++){var row=raw[ri],mc=[];for(ci=0;ci<row.length;ci++)if(isMonthH(row[ci]))mc.push({ci:ci,mi:monthIdx(row[ci])});if(mc.length>=2)sections.push({h:ri,mCols:mc,rows:[]});}
  for(si=0;si<sections.length;si++){var nx=si+1<sections.length?sections[si+1].h:raw.length;for(ri=sections[si].h+1;ri<nx;ri++)sections[si].rows.push(raw[ri]);}
  var typeMap={};
  for(ri=0;ri<raw.length;ri++){
    var tx="";for(ci=0;ci<(raw[ri]||[]).length;ci++)tx+=String(raw[ri][ci]||"").trim().toUpperCase()+" ";tx=tx.trim();
    if(tx.length<20&&tx.indexOf("INCOME")>=0)typeMap[ri]="income";else if(tx.length<20&&tx.indexOf("EXPENSE")>=0)typeMap[ri]="expense";
    else if(tx.length<15&&tx.indexOf("دخل")>=0)typeMap[ri]="income";else if(tx.length<15&&tx.indexOf("مصروف")>=0)typeMap[ri]="expense";
  }
  var inc=[],exp=[],skip=["TOTAL","BALANCE","SUMMARY","ANNUAL","AVERAGE","المجموع","PERCENTAGE"];
  for(si=0;si<sections.length;si++){
    var sec=sections[si],type="";
    for(ri=sec.h-1;ri>=Math.max(0,sec.h-5);ri--)if(typeMap[ri]){type=typeMap[ri];break;}
    if(!type)type=si===0?"income":"expense";
    var cur="";
    for(var r2=0;r2<sec.rows.length;r2++){
      var rw=sec.rows[r2],first="",lbl="";
      for(ci=0;ci<rw.length;ci++){var cv=String(rw[ci]||"").trim();if(cv&&!first)first=cv.toUpperCase();}
      if(!first)continue;
      var sk=false;for(var k=0;k<skip.length;k++)if(first.indexOf(skip[k])===0){sk=true;break;}
      if(sk)continue;
      for(ci=0;ci<sec.mCols[0].ci;ci++){var c2=String(rw[ci]||"").trim(),u=c2.toUpperCase();if(c2.length>=2&&u!=="BHD"&&u!=="KWD"&&c2!=="د.ب"){lbl=c2;break;}}
      if(!lbl)lbl=cur;if(!lbl)continue;cur=lbl;
      for(var m=0;m<sec.mCols.length;m++){
        var val=parseFloat(String(rw[sec.mCols[m].ci]||"").replace(/BHD|KWD|,/gi,"").replace(/[^0-9.]/g,""))||0;
        if(val<=0)continue;
        (type==="income"?inc:exp).push({label:lbl,amount:val,month:sec.mCols[m].mi});
      }
    }
  }
  return {incRows:inc,expRows:exp,year:new Date().getFullYear()};
}
function mapExpCat(lbl){var l=lbl.toLowerCase(),m=[["grocer","groceries"],["بقالة","groceries"],["food","food"],["طعام","food"],["debt","debt"],["loan","debt"],["دين","debt"],["child","children"],["أطفال","children"],["fuel","fuel"],["petrol","fuel"],["وقود","fuel"],["car","car"],["سيارة","car"],["health","health"],["medical","health"],["صحة","health"],["rent","home"],["house","home"],["home","home"],["بيت","home"],["electric","electricity"],["كهرباء","electricity"],["mobile","mobile"],["phone","mobile"],["موبايل","mobile"],["shop","shopping"],["مشتريات","shopping"],["entertain","entertain"],["ترفيه","entertain"],["travel","travel"],["سفر","travel"]];for(var i=0;i<m.length;i++)if(l.indexOf(m[i][0])>=0&&getCat("expense",m[i][1]).id===m[i][1])return m[i][1];return "other";}
function mapIncCat(lbl){var l=lbl.toLowerCase();if((l.indexOf("salary")>=0||l.indexOf("راتب")>=0)&&getCat("income","salary").id==="salary")return "salary";if((l.indexOf("shop")>=0||l.indexOf("متجر")>=0)&&getCat("income","shop").id==="shop")return "shop";return INC_CATS[INC_CATS.length-1].id;}
function pageConfirmXL(){
  var pd=UI.pivotData;if(!pd){UI.view="more";return pageMore();}
  var page=el("div",{sty:{minHeight:"100vh",paddingBottom:"60px"}});
  page.appendChild(hdrBar("تأكيد استيراد Excel","more"));
  var body=el("div",{cls:"content"});
  body.appendChild(secTitle("سنة البيانات"));
  var yr=inpEl({type:"number",value:String(pd.year)});body.appendChild(yr);
  function sumBy(rows){var o={};for(var i=0;i<rows.length;i++)o[rows[i].label]=(o[rows[i].label]||0)+rows[i].amount;return o;}
  function list(title,o,color){
    var k=Object.keys(o);if(!k.length)return;
    body.appendChild(secTitle(title));var c=el("div",{cls:"card"});
    for(var i=0;i<k.length;i++)c.appendChild(el("div",{cls:"tx-row",sty:{borderBottom:i<k.length-1?"1px solid var(--border)":"none"}},[el("div",{cls:"tx-info"},[el("div",{cls:"tx-name"},k[i])]),el("div",{cls:"tx-amt",sty:{color:color}},fmt(o[k[i]]))]));
    body.appendChild(c);
  }
  list("الدخل",sumBy(pd.incRows),"var(--income)");list("المصروفات",sumBy(pd.expRows),"var(--expense)");
  var n=pd.incRows.length+pd.expRows.length;
  body.appendChild(el("button",{cls:"btn",sty:{background:"var(--income)"},onclick:function(){
    var y=parseInt(yr.value,10)||pd.year,ts=Date.now(),i,t;
    var dd="-"+pad2(cycDay());
    for(i=0;i<pd.incRows.length;i++){t=pd.incRows[i];S.txs.push({id:"xl_i_"+ts+"_"+i,type:"income",catId:mapIncCat(t.label),label:t.label,amount:t.amount,date:y+"-"+pad2(t.month)+dd,note:""});}
    for(i=0;i<pd.expRows.length;i++){t=pd.expRows[i];S.txs.push({id:"xl_e_"+ts+"_"+i,type:"expense",catId:mapExpCat(t.label),label:t.label,amount:t.amount,date:y+"-"+pad2(t.month)+dd,note:""});}
    UI.pivotData=null;save();toast("✓ تم استيراد "+n+" معاملة");go("home");
  }},"✅ استيراد "+n+" معاملة"));
  body.appendChild(el("button",{cls:"btn btn-ghost",onclick:function(){UI.pivotData=null;go("more");}},"إلغاء"));
  page.appendChild(body);return page;
}

/* ═══════════════ RENDER ═══════════════ */
function render(){
  if(!S||!DKEY) return;
  if(!S.onboarded){mount(pageOnboard());return;}
  var pages={
    home:pageHome,
    incList:function(){return pageTxList("income");},
    expList:function(){return pageTxList("expense");},
    addInc:function(){UI.editTx=null;return pageAETx("income");},
    addExp:function(){UI.editTx=null;return pageAETx("expense");},
    editTx:function(){return pageAETx(UI.editTx?UI.editTx.type:"expense");},
    report:pageReport,more:pageMore,confirmXL:pageConfirmXL,
    catList:pageCatList,editCat:pageEditCat,
    commitments:pageCommits,editCommit:pageAECommit,catDetail:pageCatDetail,
    debts:pageDebts,editDebt:pageEditDebt,debtDetail:pageDebtDetail
  };
  mount((pages[UI.view]||pageHome)());
}

/* ═══════════════ LIFECYCLE ═══════════════ */
document.addEventListener("visibilitychange",function(){
  if(document.hidden){hiddenAt=Date.now();if(dirty&&!saving)flush();return;}
  if(VAULT&&VAULT.mode==="pin"&&DKEY&&hiddenAt&&Date.now()-hiddenAt>AUTOLOCK_MS) lockNow();
});
window.onerror=function(msg,src,line){
  var r=document.getElementById("root");
  if(r&&!r.firstChild){r.appendChild(el("div",{sty:{padding:"40px 20px"}},[el("h2",{sty:{color:"#E5484D",marginBottom:"10px"}},"خطأ في التطبيق"),el("p",{sty:{fontSize:"13px",color:"#666"}},String(msg||"")+" ("+line+")")]));}
  return false;
};

function boot(){
  if(!subtle||!window.TextEncoder){screenFatal("المتصفح لا يدعم التشفير. حدّث نظام جهازك أو افتح الرابط في Safari/Chrome.");return;}
  if("serviceWorker" in navigator&&location.protocol==="https:"){
    navigator.serviceWorker.register("sw.js").catch(function(){});
  }
  applyTheme();
  applyAccent();
  if(LOCAL_MODE){USER=null;LIC=null;screenLoading();openVault();return;}
  if(typeof FIREBASE_CONFIG==="undefined"||String(FIREBASE_CONFIG.apiKey).indexOf("PASTE")===0){screenSetupNeeded();return;}
  if(typeof firebase==="undefined"){screenFatal("تعذّر تحميل مكوّنات التطبيق. تحقق من الاتصال وأعد الفتح.");return;}
  screenLoading();
  firebase.initializeApp(FIREBASE_CONFIG);
  try{firebase.firestore().settings({experimentalAutoDetectLongPolling:true});}catch(e){}
  firebase.auth().onAuthStateChanged(function(user){
    S=null;RAW=null;DKEY=null;VAULT=null;LIC=null;UI.view="home";UI.tab="home";
    USER=user;
    if(!user){screenLogin();return;}
    screenLoading("جاري التحقق من الاشتراك…");
    checkLicense(user).then(afterLicense);
  });
}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",boot);else boot();

})();
