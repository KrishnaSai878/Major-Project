(function(){
  var meta = document.getElementById('scanMeta');
  if(!meta) return;
  async function checkIn(){
    var api = meta.dataset.api;
    var csrf = meta.dataset.csrf;
    var token = meta.dataset.token;
    var res = await fetch(api, { method:'POST', headers:{ 'Content-Type':'application/json', 'X-CSRFToken': csrf }, body: JSON.stringify({ token: token }) });
    var data = await res.json();
    if(res.ok){ alert('Checked in!'); window.location.href = meta.dataset.back; }
    else { alert(data.error || 'Failed'); }
  }
  var btn = document.getElementById('checkInBtn');
  if(btn) btn.addEventListener('click', function(e){ e.preventDefault(); checkIn(); });
})();
