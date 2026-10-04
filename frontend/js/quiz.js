let Q=[];
api("/quiz").then(q=>{Q=q;document.getElementById("q").innerHTML=q.map((x,i)=>`<div style="margin-bottom:1rem"><b>${i+1}. [${esc(x.category)}]</b> ${esc(x.question)}${Object.entries(x.options).map(([k,v])=>`<label class="opt"><input type="radio" name="${esc(x.id)}" value="${k}"> ${k}. ${esc(v)}</label>`).join("")}</div>`).join("");}).catch(e=>{document.getElementById("q").textContent=e.message;});
document.getElementById("submit").onclick=async()=>{
 const answers={};Q.forEach(x=>{const c=document.querySelector(`input[name="${x.id}"]:checked`);if(c)answers[x.id]=c.value;});
 try{const r=await api("/quiz/submit",{method:"POST",body:JSON.stringify({answers})});
 document.getElementById("result").innerHTML=`<div class="card"><h1>${esc(r.overall_score)}/100 - ${esc(r.level)}</h1><p class="sub">${esc(r.disclaimer)}</p>
 <h2>Category scores</h2><table>${Object.entries(r.category_scores).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${esc(v)}%</td><td style="width:50%"><div class="bar" style="width:${v}%"></div></td></tr>`).join("")}</table>
 <h2>Weakest areas</h2><p>${r.weakest_areas.map(esc).join(", ")}</p><h2>Learning recommendations</h2><ul>${r.recommendations.map(x=>`<li>${esc(x.category)} (${esc(x.score)}%): ${esc(x.recommendation)}${x.module_id?` - <a href="awareness.html#${esc(x.module_id)}">open module</a>`:""}</li>`).join("")}</ul>
 <h2>Answer review</h2>${r.results.filter(x=>!x.correct).map(x=>`<p class="bad">${esc(x.id)}: correct answer ${esc(x.correct_answer)}. <span class="sub">${esc(x.explanation)}</span></p>`).join("")||"<p class='ok'>All correct!</p>"}</div>`;
 scrollTo(0,document.body.scrollHeight);}catch(e){alert(e.message);}};
