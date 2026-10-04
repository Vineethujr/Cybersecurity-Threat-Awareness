// Shared helpers. IMPORTANT: every dynamic value goes through esc() (XSS defence).
const PAGES=[["index.html","Home"],["threat-dashboard.html","Dashboard"],["awareness.html","Awareness"],["quiz.html","Quiz"]];
function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function badge(s){return `<span class="badge ${esc(s)}">${esc(s)}</span>`;}
function ent(s){return `<span class="badge ent ${esc(s)}">${esc(s)}</span>`;}
function fmt(t){return esc(String(t||"").replace("T"," ").slice(0,16));}
async function api(path,opts={}){
  const key=sessionStorage.getItem("apiKey");
  const headers={"Content-Type":"application/json",...(key?{"X-API-Key":key}:{})};
  const r=await fetch("/api"+path,{headers,...opts});
  const data=await r.json().catch(()=>({}));
  if(!r.ok)throw new Error(data.error||("HTTP "+r.status));
  return data;
}
function askKey(){const k=prompt("Analyst API key (demo default: demo-analyst-key)");if(k)sessionStorage.setItem("apiKey",k.trim());return !!k;}
async function write(path,method,body){
  if(!sessionStorage.getItem("apiKey")&&!askKey())throw new Error("API key required");
  try{return await api(path,{method,body:JSON.stringify(body)});}
  catch(e){if(/key/i.test(e.message)){sessionStorage.removeItem("apiKey");}throw e;}
}
function nav(){
  const here=location.pathname.split("/").pop()||"index.html";
  const el=document.getElementById("nav");
  el.innerHTML=`<nav aria-label="Main navigation"><a class="brand" href="index.html">Threat Intel &amp; Awareness</a><div class="nav-links">`+PAGES.map(([h,t])=>`<a href="${h}" class="${h===here||(here==='threat-details.html'&&h==='threat-dashboard.html')?'on':''}"${h===here||(here==='threat-details.html'&&h==='threat-dashboard.html')?' aria-current="page"':''}>${t}</a>`).join("")+ 
   `</div><span class="nav-note">Synthetic / demo data only</span></nav>`;
}
document.addEventListener("DOMContentLoaded",nav);
