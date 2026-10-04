const ul=a=>"<ul>"+a.map(x=>`<li>${esc(x)}</li>`).join("")+"</ul>";
api("/awareness/modules").then(m=>{
 const hash=location.hash.slice(1);
 document.getElementById("mods").innerHTML=m.map(x=>`<details id="${esc(x.id)}" ${x.id===hash?"open":""}><summary>${esc(x.title)}</summary>
 <h2>What is it?</h2><p>${esc(x.what)}</p><h2>Why does it matter?</h2><p>${esc(x.why)}</p><h2>Warning signs</h2>${ul(x.warning_signs)}<h2>Safe practices</h2>${ul(x.safe_practices)}<h2>If something happens</h2>${ul(x.if_it_happens)}</details>`).join("");
}).catch(e=>{document.getElementById("mods").textContent=e.message;});
