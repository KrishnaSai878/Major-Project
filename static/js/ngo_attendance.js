(function(){
  var meta = document.getElementById('attendanceMeta');
  if(!meta) return;
  async function generateToken(){
    var eventId = parseInt(meta.dataset.eventId,10);
    var tsId = meta.dataset.timeSlotId ? parseInt(meta.dataset.timeSlotId,10) : null;
    var body = { event_id: eventId, time_slot_id: tsId };
    var res = await fetch(meta.dataset.api, { method:'POST', headers:{ 'Content-Type':'application/json', 'X-CSRFToken': meta.dataset.csrf }, body: JSON.stringify(body) });
    var data = await res.json();
    if(res.ok){ var box = document.getElementById('tokenBox'); if(box) box.innerText = 'Token: '+data.token+' (expires in '+data.ttl_minutes+'m)'; }
    else { alert(data.error || 'Failed'); }
  }
  var btn = document.getElementById('generateTokenBtn');
  if(btn) btn.addEventListener('click', function(e){ e.preventDefault(); generateToken(); });
})();
