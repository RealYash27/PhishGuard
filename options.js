
async function load(){
  const d = await chrome.storage.sync.get({onlineDeepChecksEnabled:false, vtKey:"", urlscanKey:""});
  document.getElementById("online").checked = d.onlineDeepChecksEnabled;
  document.getElementById("vt").value = d.vtKey || "";
  document.getElementById("us").value = d.urlscanKey || "";
}
async function save(){
  await chrome.storage.sync.set({
    onlineDeepChecksEnabled: document.getElementById("online").checked,
    vtKey: document.getElementById("vt").value.trim(),
    urlscanKey: document.getElementById("us").value.trim()
  });
  const ok=document.getElementById("ok"); ok.style.display="inline"; setTimeout(()=>ok.style.display="none",1500);
}
document.getElementById("save").onclick=save;
document.addEventListener("DOMContentLoaded", load);
