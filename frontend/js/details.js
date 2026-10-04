const id=new URLSearchParams(location.search).get("id");
async function load(){
 const t=await api("/threats/"+encodeURIComponent(id));
 const dl=r=>"<dl>"+r.map(([k,v])=>`<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")+"</dl>";
 document.getElementById("out").innerHTML=`
 <h1>${esc(t.threat_id)} - ${esc(t.threat_name)}</h1><p>${badge(t.severity)} ${ent(t.entity_type)} <span class="sub">Classification: OBSERVATION &lt; INDICATOR &lt; ALERT &lt; THREAT &lt; INCIDENT (incident only when an admin confirms)</span></p>
 <div class="note">${esc(t.interpretation)} Risk = how concerning; Confidence = how much we trust the evidence. Neither proves compromise.</div>
 <div class="grid g2"><div class="card"><h2>Overview</h2>${dl([["Category",t.category],["Description",t.description],["Indicator type",t.indicator_type],["Indicator value",t.indicator_value],["Risk score",t.risk_score+"/100"],["Confidence",t.confidence_score+"/100"],["Source",t.source_name],["Source reliability",t.reliability+" - "+t.reliability_label],["First seen",fmt(t.first_seen)],["Last seen",fmt(t.last_seen)],["Observations",t.observation_count],["Region",t.country_or_region||"n/a"],["CVE",t.cve_id||"n/a"],["Status",t.status]])}</div>
 <div class="card"><h2>MITRE ATT&amp;CK</h2>${t.attack_mappings.length?t.attack_mappings.map(m=>`<p><b>${esc(m.tactic)}</b> - ${esc(m.technique)} <span class="mono">${esc(m.technique_id_optional)}</span></p>`).join(""):"<p>Not mapped.</p>"}<p class="sub">${esc(t.attack_note)}</p>
 <h2>Recommended defensive actions</h2><ul>${t.recommended_actions.map(a=>`<li>${esc(a)}</li>`).join("")}</ul><p class="sub">${esc(t.category_guidance.awareness)}</p></div>
 <div class="card"><h2>Related indicators</h2><p class="sub">${esc(t.cluster_note)}</p>${t.related_indicators.map(r=>`<p><a href="threat-details.html?id=${encodeURIComponent(r.threat_id)}">${esc(r.threat_id)}</a> <span class="mono">${esc(r.indicator_value)}</span> (${esc(r.indicator_type)})</p>`).join("")||"<p>None.</p>"}
 <h2>Related alerts</h2>${t.alerts.map(a=>`<p>${esc(a.alert_id)} ${badge(a.severity)} ${esc(a.alert_type)} - ${esc(a.status)}</p>`).join("")||"<p>None.</p>"}
 ${t.vulnerability?`<h2>CVE association (synthetic)</h2>${dl([["CVE",t.vulnerability.cve_id],["CVSS",t.vulnerability.cvss_score],["Priority",t.vulnerability.priority_score],["Patch available",t.vulnerability.patch_available?"yes":"no"]])}`:""}</div>
 <div class="card"><h2>Investigation timeline</h2><div class="tl">${t.timeline.map(e=>`<div><b>${esc(e.event)}</b> <span class="sub">${fmt(e.time)}</span><br>${esc(e.detail)}</div>`).join("")}</div></div></div>
 <div class="card" style="margin-top:12px"><h2>Analyst notes &amp; workflow</h2><div id="notes">${t.notes.map(n=>`<p>${esc(n.note)} <span class="sub">${esc(n.author_role)}, ${fmt(n.created_at)}</span></p>`).join("")||"<p class='sub'>No notes yet.</p>"}</div>
 <div class="filters"><input id="note" size="60" placeholder="Add analyst note"><button class="btn" id="addn">Add note</button>
 <select id="st">${["NEW","UNDER_REVIEW","MONITORING","CLOSED","FALSE_POSITIVE"].map(s=>`<option ${s===t.status?"selected":""}>${s}</option>`).join("")}</select><button class="btn alt" id="upd">Update status</button></div><p class="sub" id="msg">Write actions need an analyst API key (you will be prompted).</p></div>`;
 document.getElementById("addn").onclick=async()=>{try{await write(`/threats/${encodeURIComponent(id)}/notes`,"POST",{note:document.getElementById("note").value});load();}catch(e){document.getElementById("msg").textContent=e.message;}};
 document.getElementById("upd").onclick=async()=>{try{await write(`/threats/${encodeURIComponent(id)}`,"PUT",{status:document.getElementById("st").value});load();}catch(e){document.getElementById("msg").textContent=e.message;}};
}
load().catch(e=>{document.getElementById("out").textContent=e.message;});
