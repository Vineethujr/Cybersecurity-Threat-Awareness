(async()=>{
 const d=await api("/dashboard/executive"),c=d.cards;
 document.getElementById("headline").textContent=d.headline;
 const k=[["Critical severity",c.critical_threats],["High severity",c.high_threats],["Open alerts",c.open_alerts],["Vulnerabilities tracked",c.vulnerabilities_tracked]];
 document.getElementById("kpis").innerHTML=k.map(([l,n])=>`<div class="card kpi"><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`).join("");
 const bars=(a,max)=>a.map(x=>`<div>${esc(x.label)} <span class="sub">${esc(x.count??x.score)}</span><div class="bar" style="width:${Math.round(100*(x.count??x.score)/max)}%"></div></div>`).join("");
 const cm=Math.max(...d.top_threat_categories.map(x=>x.count),1),vm=Math.max(...d.top_vulnerability_categories.map(x=>x.count),1);
 document.getElementById("cats").innerHTML=bars(d.top_threat_categories,cm);
 document.getElementById("vcats").innerHTML=bars(d.top_vulnerability_categories,vm);
 document.getElementById("weak").innerHTML=bars(d.top_awareness_weaknesses,100)+'<p class="sub">Lower score = topic needing more learning support.</p>';
 document.getElementById("prio").innerHTML=d.priorities.map(p=>`<li>${esc(p)}</li>`).join("");
 document.getElementById("disc").textContent=d.disclaimer;
 new Chart(document.getElementById("trend"),{type:"line",data:{labels:d.awareness_trend.map(x=>x.label),datasets:[{label:"Average score",data:d.awareness_trend.map(x=>x.count),borderColor:"#f2b134",tension:.3}]},options:{maintainAspectRatio:false,scales:{y:{min:0,max:100}}}});
})().catch(e=>{document.getElementById("headline").textContent="Could not load data: "+e.message;});
