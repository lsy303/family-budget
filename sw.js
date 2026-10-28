/* ميزانية البيت — Service Worker (لا يخزّن أي بيانات مالية؛ فقط ملفات التطبيق) */
var CACHE = "mb-v25.3";
var CORE = ["./","index.html","app.js","firebase-config.js","manifest.json",
  "vendor/firebase-app-compat.js","vendor/firebase-auth-compat.js","vendor/firebase-firestore-compat.js",
  "vendor/xlsx.full.min.js","icons/icon-192.png","icons/apple-touch-icon.png"];
self.addEventListener("install",function(e){e.waitUntil(caches.open(CACHE).then(function(c){return c.addAll(CORE);}).then(function(){return self.skipWaiting();}));});
self.addEventListener("activate",function(e){e.waitUntil(caches.keys().then(function(ks){return Promise.all(ks.filter(function(k){return k!==CACHE;}).map(function(k){return caches.delete(k);}));}).then(function(){return self.clients.claim();}));});
self.addEventListener("fetch",function(e){
  var req=e.request,url=new URL(req.url);
  if(req.method!=="GET")return;
  /* fonts: cache-first */
  if(url.host==="fonts.googleapis.com"||url.host==="fonts.gstatic.com"){
    e.respondWith(caches.match(req).then(function(hit){return hit||fetch(req).then(function(res){var cp=res.clone();caches.open(CACHE).then(function(c){c.put(req,cp);});return res;});}));
    return;
  }
  if(url.origin!==self.location.origin)return;           /* never touch Firebase traffic */
  if(url.pathname.indexOf("admin")>=0)return;             /* admin page always live */
  /* app files: network-first so updates arrive immediately */
  e.respondWith(fetch(req).then(function(res){
    if(res&&res.ok){var cp=res.clone();caches.open(CACHE).then(function(c){c.put(req,cp);});}
    return res;
  }).catch(function(){return caches.match(req,{ignoreSearch:true}).then(function(h){return h||caches.match("index.html");});}));
});
