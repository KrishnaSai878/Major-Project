(function(){
  try {
    var container = document.getElementById('toastContainer');
    if(!container) return;
    var raw = container.getAttribute('data-flashes') || '[]';
    var messages = [];
    try { messages = JSON.parse(raw); } catch(e) { messages = []; }
    var iconMap = { success: 'fa-check-circle', error: 'fa-exclamation-circle', info: 'fa-info-circle' };
    messages.forEach(function(item){
      var level = (item[0] === 'error') ? 'error' : (item[0] || 'info');
      var icon = iconMap[level] || iconMap.info;
      var el = document.createElement('div');
      el.className = 'toast toast-' + level;
      el.innerHTML = '<i class="fas ' + icon + ' toast-icon"></i>' +
                     '<div>' + item[1] + '</div>' +
                     '<button class="toast-close" aria-label="Close">&times;</button>';
      el.querySelector('.toast-close').addEventListener('click', function(){ el.remove(); });
      container.appendChild(el);
      setTimeout(function(){ el.remove(); }, 5000);
    });
  } catch (e) { /* noop */ }
})();

// Mobile nav toggle
(function(){
  try {
    var btn = document.getElementById('navToggle');
    var nav = document.getElementById('mainNav');
    if(!btn || !nav) return;
    btn.addEventListener('click', function(){
      if(nav.classList.contains('open')){ nav.classList.remove('open'); }
      else { nav.classList.add('open'); }
    });
  } catch(e) { /* noop */ }
})();
