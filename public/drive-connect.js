document.addEventListener('DOMContentLoaded', function () {
  var form = document.getElementById('drive-connect-check');
  var status = document.getElementById('drive-connect-status');
  if (!form || !status) return;

  var action = form.getAttribute('action');
  var tokenInput = form.querySelector('input[name="_csrf"]');
  var token = tokenInput ? tokenInput.value : '';
  var started = Date.now();
  var MAX_WAIT = 10 * 60 * 1000;

  function check() {
    if (Date.now() - started > MAX_WAIT) {
      status.textContent = 'This request expired. Start again from Settings → Drive.';
      return;
    }
    fetch(action, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'X-CSRF-Token': token,
        'X-Requested-With': 'XMLHttpRequest'
      },
      credentials: 'same-origin'
    }).then(function (r) {
      return r.json();
    }).then(function (data) {
      if (data.status === 'connected') {
        window.location = '/settings/drive?notice=' + encodeURIComponent(data.message || 'Connected.');
      } else if (data.status === 'error') {
        status.textContent = data.message || 'Could not connect.';
      } else {
        setTimeout(check, 3000);
      }
    }).catch(function () {
      setTimeout(check, 5000);
    });
  }

  setTimeout(check, 2500);
});
