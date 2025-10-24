(function(){
  var meta = document.getElementById('donateMeta');
  if(!meta) return;

  function buildUpiLink() {
    var upiId = meta.dataset.upiId || '';
    var upiName = meta.dataset.upiName || '';
    var amtInput = document.getElementById('amount_inr');
    var msgInput = document.getElementById('message');
    var amount = (amtInput && amtInput.value) ? parseFloat(amtInput.value) : null;
    var note = (msgInput && msgInput.value) ? msgInput.value : (meta.dataset.message || 'Donation');

    var params = new URLSearchParams();
    if (upiId) params.set('pa', upiId); // payee address
    if (upiName) params.set('pn', upiName); // payee name
    if (amount && amount > 0) params.set('am', amount.toFixed(2)); // amount
    params.set('cu', 'INR'); // currency
    if (note) params.set('tn', note.slice(0, 40)); // transaction note (short)

    return 'upi://pay?' + params.toString();
  }

  function renderUpiQr() {
    var upiUrl = buildUpiLink();
    var qrImg = document.getElementById('upiQrImg');
    var link = document.getElementById('upiLink');
    if (link) link.href = upiUrl;
    if (qrImg) {
      var enc = encodeURIComponent(upiUrl);
      qrImg.src = 'https://api.qrserver.com/v1/create-qr-code/?data=' + enc + '&size=220x220&margin=2';
    }
  }

  // Initial QR/link render
  if (meta.dataset.upiId) {
    // Prefill amount and message from data attributes if present
    try {
      var amt = meta.dataset.amount;
      if (amt) { var amtEl = document.getElementById('amount_inr'); if (amtEl && !amtEl.value) amtEl.value = amt; }
      var msg = meta.dataset.message;
      if (msg) { var msgEl = document.getElementById('message'); if (msgEl && !msgEl.value) msgEl.value = msg; }
    } catch (e) {}
    renderUpiQr();
    // Update QR when amount or message changes
    var amtEl2 = document.getElementById('amount_inr');
    var msgEl2 = document.getElementById('message');
    if (amtEl2) amtEl2.addEventListener('input', renderUpiQr);
    if (msgEl2) msgEl2.addEventListener('input', renderUpiQr);
  }

  async function confirmDonation(){
    var api = meta.dataset.api;
    var csrf = meta.dataset.csrf;
    var ngoId = meta.dataset.ngoId ? parseInt(meta.dataset.ngoId,10) : null;
    var amt = parseFloat(document.getElementById('amount_inr').value || 0);
    var msg = document.getElementById('message').value || '';
    var anon = document.getElementById('anonymous').checked;
    var ref = (document.getElementById('upi_reference').value || '').trim();
    var payload = { ngo_id: ngoId, amount_inr: amt, message: msg, anonymous: anon, upi_reference: ref };
    var res = await fetch(api, { method:'POST', headers:{ 'Content-Type':'application/json', 'X-CSRFToken': csrf }, body: JSON.stringify(payload) });
    var data = await res.json();
    if(res.ok){ alert('Donation recorded. ID: '+data.donation_id); window.location.href = meta.dataset.back; }
    else { alert(data.error || 'Failed'); }
  }
  var btn = document.getElementById('donateConfirm');
  if(btn) btn.addEventListener('click', function(e){ e.preventDefault(); confirmDonation(); });
})();
