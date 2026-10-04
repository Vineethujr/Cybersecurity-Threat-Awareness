const TABS=[["overview","Overview"],["threats","Threats"],["search","IOC Search"],["alerts","Alerts"],["attack","ATT&CK"],["vulns","Vulnerabilities"]];
const COL=["#f2b134","#4cc38a","#f07a3c","#e5484d","#5aa9e6","#a78bfa","#6b7f96","#2dd4bf","#f472b6","#84cc16"];
const $=id=>document.getElementById(id);let page=1,loaded={};
$("tabs").innerHTML=TABS.map(([k,t])=>`<button data-k="${k}">${t}</button>`).join("");
$("tabs").onclick=e=>{const k=e.target.dataset.k;if(k)show(k);};
function show(k){TABS.forEach(([x])=>$("t-"+x).classList.toggle("hidden",x!==k));
 [...$("tabs").children].forEach(b=>b.classList.toggle("on",b.dataset.k===k));
 if(!loaded[k]){loaded[k]=1;({overview,threats:loadThreats,alerts:loadAlerts,attack:loadAttack,vulns:loadVulns,search(){}})[k]();}}
function chart(title,type,rows,cols=COL){const d=document.createElement("div");d.className="card";d.innerHTML=`<h2>${esc(title)}</h2><div class="chart"><canvas></canvas></div>`;$("charts").append(d);
 new Chart(d.querySelector("canvas"),{type,data:{labels:rows.map(r=>r.label),datasets:[{data:rows.map(r=>r.count),backgroundColor:cols,borderColor:"#152030"}]},options:{maintainAspectRatio:false,plugins:{legend:{display:type!=="bar"&&type!=="line",labels:{color:"#dbe6f3"}}},scales:type==="bar"||type==="line"?{x:{ticks:{color:"#8fa3ba"}},y:{ticks:{color:"#8fa3ba"}}}:{}}});}
async function overview(){
 const [s,t]=await Promise.all([api("/dashboard/stats"),api("/dashboard/trends")]),c=s.cards,ch=s.charts;
 const k=[["Total threat records",c.total_threats],["Critical threats",c.critical_threats],["High threats",c.high_threats],["Active indicators",c.active_indicators],["Open investigations",c.open_investigations],["Average confidence",c.average_confidence+"%"],["Vulnerabilities tracked",c.vulnerabilities_tracked],["Open alerts",c.open_alerts]];
 $("kpis").innerHTML=k.map(([l,n])=>`<div class="card kpi"><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`).join("");
 chart("Threats over time (first seen, monthly)","line",t.labels.map((l,i)=>({label:l,count:t.total[i]})),["#f2b134"]);
 chart("Threats by severity","doughnut",ch.severity,["#6b7f96","#4cc38a","#f2b134","#f07a3c","#e5484d"]);
 chart("Threats by category","bar",ch.category);chart("IOC type distribution","doughnut",ch.ioc_types);
 chart("Top ATT&CK tactics (evidence-gated)","bar",ch.tactics);chart("Risk score distribution","bar",ch.risk_distribution,["#f2b134"]);
 chart("Confidence distribution","bar",ch.confidence_distribution,["#4cc38a"]);chart("Vulnerabilities by severity","bar",ch.vuln_severity,["#f07a3c"]);
 chart("Top threat categories","doughnut",ch.top_categories);chart("Threat status distribution","doughnut",ch.status);}
const SEV=["INFORMATIONAL","LOW","MEDIUM","HIGH","CRITICAL"],CAT=["PHISHING","MALWARE","RANSOMWARE","CREDENTIAL THREATS","WEB THREATS","NETWORK THREATS","VULNERABILITY EXPOSURE","SOCIAL ENGINEERING","DATA EXPOSURE","ACCOUNT SECURITY"],
 IT=["IP_ADDRESS","DOMAIN","URL","FILE_HASH","EMAIL_DOMAIN","CVE_ID"],ST=["NEW","UNDER_REVIEW","MONITORING","CLOSED","FALSE_POSITIVE"];
const sel=(id,ph,a)=>`<select id="${id}"><option value="">${ph}</option>${a.map(x=>`<option>${x}</option>`).join("")}</select>`;
$("filters").innerHTML=`<input id="fq" placeholder="Search id / name / indicator">${sel("fsev","Severity",SEV)}${sel("fcat","Category",CAT)}${sel("fit","Indicator type",IT)}${sel("fst","Status",ST)}
 <input id="fr" type="number" min="0" max="100" placeholder="Min risk" style="width:95px"><input id="fc" type="number" min="0" max="100" placeholder="Min conf." style="width:95px">
 <input id="fd" type="date" title="Last seen from"><select id="fs"><option value="newest">Newest</option><option value="risk">Highest risk</option><option value="confidence">Highest confidence</option><option value="observed">Most observed</option></select><button class="btn" id="apply">Apply</button>`;
$("apply").onclick=()=>{page=1;loadThreats();};$("prev").onclick=()=>{if(page>1){page--;loadThreats();}};$("next").onclick=()=>{page++;loadThreats();};
async function loadThreats(){
 const p=new URLSearchParams({page,page_size:20,sort:$("fs").value});
 [["q","fq"],["severity","fsev"],["category","fcat"],["indicator_type","fit"],["status","fst"],["min_risk","fr"],["min_confidence","fc"],["date_from","fd"]].forEach(([k,i])=>{if($(i).value)p.set(k,$(i).value);});
 try{const d=await api("/threats?"+p);
 $("tbl").innerHTML="<tr><th>ID</th><th>Name</th><th>Category</th><th>Indicator</th><th>Severity</th><th>Risk</th><th>Conf.</th><th>Type</th><th>First</th><th>Last</th><th>Status</th></tr>"+
 d.items.map(t=>`<tr class="click" data-id="${esc(t.threat_id)}"><td class="mono">${esc(t.threat_id)}</td><td>${esc(t.threat_name)}</td><td>${esc(t.category)}</td><td class="mono">${esc(t.indicator_value)}</td><td>${badge(t.severity)}</td><td>${esc(t.risk_score)}</td><td>${esc(t.confidence_score)}%</td><td>${ent(t.entity_type)}</td><td>${fmt(t.first_seen)}</td><td>${fmt(t.last_seen)}</td><td>${esc(t.status)}</td></tr>`).join("");
 $("pg").textContent=`Page ${d.page} of ${Math.max(1,Math.ceil(d.total/d.page_size))} (${d.total} records)`;}catch(e){$("pg").textContent=e.message;}}
$("tbl").onclick=e=>{const r=e.target.closest("tr[data-id]");if(r)location.href="threat-details.html?id="+encodeURIComponent(r.dataset.id);};
$("go").onclick=search;$("q").onkeydown=e=>{if(e.key==="Enter")search();};
async function search(){const q=$("q").value.trim();if(!q)return;
 try{const d=await api("/indicators/search?q="+encodeURIComponent(q));let h=`<div class="note">${esc(d.note)}</div>`;
 if(!d.validation.valid)h+=`<p class="bad">Not a valid indicator: ${esc(d.validation.validation_notes.join(" "))}</p>`;
 else if(!d.known_in_demo_dataset)h+=`<p>Indicator type: <b>${esc(d.indicator_type)}</b><br>Known in demo dataset: <b>NO</b><br>${esc(d.summary)}</p>`;
 else{const rows=[["Indicator type",d.indicator_type],["Known in demo dataset","YES"],["Risk",d.risk_score+"/100"],["Severity",d.severity],["Confidence",d.confidence+"%"],["Associated category",d.associated_categories.join(", ")],["First seen",fmt(d.first_seen)],["Last seen",fmt(d.last_seen)],["Status",d.status],["Observations",d.observation_count],["Source",d.source+" (reliability "+d.source_reliability+")"],["ATT&CK",d.mitre_mapping.map(m=>m.technique+" ("+m.technique_id_optional+")").join(", ")||"Not mapped (insufficient evidence)"],["Related indicators",d.related_indicators.map(r=>r.indicator_value).join(", ")||"none"],["Related alerts",d.related_alerts.map(a=>a.alert_id+" "+a.status).join(", ")||"none"],["Interpretation",d.interpretation]];
 h+="<dl>"+rows.map(([k,v])=>`<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")+"</dl>"+d.threat_ids.slice(0,5).map(i=>`<p><a href="threat-details.html?id=${encodeURIComponent(i)}">Open ${esc(i)}</a></p>`).join("")+`<div class="note">${esc(d.summary)}</div>`;}
 $("res").innerHTML=h;}catch(e){$("res").innerHTML=`<p class="bad">${esc(e.message)}</p>`;}}
async function loadAlerts(){const a=await api("/alerts?limit=100");
 $("atbl").innerHTML="<tr><th>Alert</th><th>Threat</th><th>Type</th><th>Severity</th><th>Risk</th><th>Conf.</th><th>Obs.</th><th>Status</th></tr>"+a.map(x=>`<tr><td class="mono">${esc(x.alert_id)}</td><td><a href="threat-details.html?id=${encodeURIComponent(x.threat_id)}">${esc(x.threat_name)}</a></td><td>${esc(x.alert_type)}</td><td>${badge(x.severity)}</td><td>${esc(x.risk_score)}</td><td>${esc(x.confidence_score)}%</td><td>${esc(x.observation_count)}</td>
 <td><select data-a="${esc(x.alert_id)}">${["NEW","INVESTIGATING","MONITORING","RESOLVED","FALSE_POSITIVE"].map(s=>`<option ${s===x.status?"selected":""}>${s}</option>`).join("")}</select></td></tr>`).join("");}
$("atbl").onchange=async e=>{const id=e.target.dataset.a;if(!id)return;try{await write(`/alerts/${encodeURIComponent(id)}/status`,"PUT",{status:e.target.value});}catch(x){alert(x.message);loaded.alerts=0;loadAlerts();}};
async function loadAttack(){const a=await api("/attack/summary");
 chart_simple(a.tactics);$("anote").textContent=a.note+" Unmapped records: "+a.unmapped_threats+".";
 $("tech").innerHTML="<tr><th>Technique</th><th>ID</th><th>Tactic</th><th>Records</th></tr>"+a.techniques.map(t=>`<tr class="click" data-t="${esc(t.technique_id)}" data-name="${esc(t.technique)}" data-tactic="${esc(t.tactic)}"><td>${esc(t.technique)}</td><td class="mono">${esc(t.technique_id)}</td><td>${esc(t.tactic)}</td><td>${esc(t.count)}</td></tr>`).join("");}
function chart_simple(rows){new Chart($("cTac"),{type:"bar",data:{labels:rows.map(r=>r.label),datasets:[{data:rows.map(r=>r.count),backgroundColor:"#f2b134"}]},options:{indexAxis:"y",maintainAspectRatio:false,plugins:{legend:{display:false}}}});}
let selectedTechniqueId="";
$("tech").onclick=async e=>{const r=e.target.closest("tr[data-t]");if(!r)return;
 selectedTechniqueId=r.dataset.t;
 $("tech").querySelectorAll("tr[data-t]").forEach(row=>row.classList.toggle("is-selected",row===r));
 $("selected-technique").textContent=`Selected technique: ${r.dataset.name} (${r.dataset.t}) - ${r.dataset.tactic}`;
 $("thead").textContent=`Records mapped to ${r.dataset.name} (${r.dataset.t})`;
 $("trec").innerHTML="<tr><td colspan=\"6\">Loading records...</td></tr>";
 try{const d=await api("/attack/techniques/"+encodeURIComponent(r.dataset.t));
  if(selectedTechniqueId!==r.dataset.t)return;
  $("trec").innerHTML="<tr><th>ID</th><th>Name</th><th>Indicator</th><th>Risk</th><th>Conf.</th><th>Status</th></tr>"+d.map(t=>`<tr><td><a href="threat-details.html?id=${encodeURIComponent(t.threat_id)}">${esc(t.threat_id)}</a></td><td>${esc(t.threat_name)}</td><td class="mono">${esc(t.indicator_value)}</td><td>${esc(t.risk_score)}</td><td>${esc(t.confidence_score)}%</td><td>${esc(t.status)}</td></tr>`).join("");
 }catch(error){if(selectedTechniqueId===r.dataset.t)$("trec").innerHTML=`<tr><td class="bad" colspan="6">Unable to load records: ${esc(error.message)}</td></tr>`;}};
async function loadVulns(){const v=await api("/vulnerabilities");
 $("vtbl").innerHTML="<tr><th>CVE (synthetic)</th><th>Product</th><th>Severity</th><th>CVSS</th><th>Exposure</th><th>Asset crit.</th><th>Exploitation (demo)</th><th>Patch</th><th>Priority</th></tr>"+v.map(x=>`<tr><td class="mono">${esc(x.cve_id)}</td><td>${esc(x.product_category)}</td><td>${badge(x.severity)}</td><td>${esc(x.cvss_score)}</td><td>${esc(x.exposure)}</td><td>${esc(x.asset_criticality)}</td><td>${esc(x.exploitation_status_demo)}</td><td>${x.patch_available?"yes":"no"}</td><td><b>${esc(x.priority_score)}</b></td></tr>`).join("");}
show("overview");
