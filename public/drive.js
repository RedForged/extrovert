document.addEventListener('DOMContentLoaded', function () {
  var form = document.getElementById('driveUpload');
  if (!form) return;
  var input = document.getElementById('drive-file');
  var warn = document.getElementById('driveWarn');
  var remaining = parseInt(form.getAttribute('data-remaining'), 10);
  if (!input || !Number.isFinite(remaining)) return;

  function check() {
    var file = input.files && input.files[0];
    if (!file || file.size <= remaining) {
      if (warn) warn.hidden = true;
      input.setCustomValidity('');
      return true;
    }
    if (warn) {
      warn.textContent = 'That file needs ' + human(file.size) + ' but only ' + human(remaining) + ' is left in your Drive.';
      warn.hidden = false;
    }
    input.setCustomValidity('Not enough Drive space.');
    return false;
  }

  function human(bytes) {
    if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    if (bytes >= 1024) return Math.round(bytes / 1024) + ' KB';
    return bytes + ' B';
  }

  input.addEventListener('change', check);
  form.addEventListener('submit', function (e) {
    if (!check()) e.preventDefault();
  });
});
