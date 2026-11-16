document.addEventListener('DOMContentLoaded', function () {
  var form = document.getElementById('driveUpload');
  if (!form) return;
  var input = document.getElementById('drive-file');
  var warn = document.getElementById('driveWarn');
  var button = document.getElementById('driveUploadBtn');
  var panel = document.getElementById('driveUploadProgress');
  var nameEl = document.getElementById('driveUploadName');
  var pctEl = document.getElementById('driveUploadPct');
  var bar = document.getElementById('driveUploadBar');
  var fill = document.getElementById('driveUploadFill');
  var statusEl = document.getElementById('driveUploadStatus');
  if (!input || !panel || !bar || !fill || !statusEl) return;

  var remainingAttr = form.getAttribute('data-remaining');
  var remaining = remainingAttr === null ? null : parseInt(remainingAttr, 10);
  if (!Number.isFinite(remaining)) remaining = null;
  var backend = form.getAttribute('data-backend') || 'local';
  var uploading = false;

  function human(bytes) {
    if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    if (bytes >= 1024) return Math.round(bytes / 1024) + ' KB';
    return bytes + ' B';
  }

  function setWarn(message) {
    if (!warn) return;
    warn.textContent = message || '';
    warn.hidden = !message;
  }

  function check() {
    var file = input.files && input.files[0];
    if (!file) {
      setWarn('');
      input.setCustomValidity('');
      return false;
    }
    if (remaining === null || file.size <= remaining) {
      setWarn('');
      input.setCustomValidity('');
      return true;
    }
    setWarn('That file needs ' + human(file.size) + ' but only ' + human(remaining) + ' is left in your Drive.');
    input.setCustomValidity('Not enough Drive space.');
    return false;
  }

  function setProgress(pct) {
    var value = Math.max(0, Math.min(100, Math.round(pct)));
    fill.style.width = value + '%';
    pctEl.textContent = value + '%';
    bar.setAttribute('aria-valuenow', String(value));
  }

  function setStatus(message, isError) {
    statusEl.textContent = message;
    statusEl.classList.toggle('error', !!isError);
  }

  function parseResponse(xhr) {
    try {
      return JSON.parse(xhr.responseText);
    } catch (e) {
      return null;
    }
  }

  function errorMessage(xhr, data) {
    if (data && (data.message || data.error)) return data.message || data.error;
    var text = String(xhr.responseText || '').trim();
    if (text && text.charAt(0) !== '<') return text.slice(0, 240);
    if (xhr.status === 413) return 'That upload exceeds the space left in your Drive.';
    return 'Upload failed (' + (xhr.status || 'network error') + ').';
  }

  function fail(message) {
    uploading = false;
    panel.classList.remove('saving');
    panel.classList.add('error');
    setStatus(message || 'Upload failed.', true);
    button.disabled = false;
    input.disabled = false;
    form.classList.remove('is-uploading');
  }

  function start() {
    var file = input.files[0];
    if (!file) return;

    uploading = true;
    setWarn('');
    panel.hidden = false;
    panel.classList.remove('saving', 'error');
    nameEl.textContent = file.name;
    setProgress(0);
    setStatus('Starting upload…', false);
    button.disabled = true;
    form.classList.add('is-uploading');
    input.setCustomValidity('');

    // Capture the file before disabling the picker.
    var payload = new FormData(form);
    input.disabled = true;

    var csrf = (form.querySelector('input[name="_csrf"]') || {}).value || '';
    var xhr = new XMLHttpRequest();
    xhr.open('POST', form.action, true);
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
    xhr.setRequestHeader('Accept', 'application/json');
    if (csrf) xhr.setRequestHeader('X-CSRF-Token', csrf);

    xhr.upload.addEventListener('progress', function (ev) {
      if (!ev.lengthComputable) return;
      setProgress((ev.loaded / ev.total) * 100);
      setStatus('Uploading ' + human(ev.loaded) + ' of ' + human(ev.total) + '…', false);
    });

    // The body is on the server; a Nextcloud backend may still be writing it
    // to the user's storage before it answers.
    xhr.upload.addEventListener('load', function () {
      setProgress(100);
      panel.classList.add('saving');
      setStatus(backend === 'nextcloud' ? 'Saving to your Nextcloud…' : 'Finishing…', false);
    });

    xhr.addEventListener('load', function () {
      var data = parseResponse(xhr);
      if (xhr.status >= 200 && xhr.status < 300) {
        panel.classList.remove('saving');
        setProgress(100);
        setStatus('Uploaded — refreshing…', false);
        setTimeout(function () {
          window.location.assign('/drive');
        }, 600);
        return;
      }
      fail(errorMessage(xhr, data));
    });

    xhr.addEventListener('error', function () {
      fail('Network error — the upload did not finish.');
    });
    xhr.addEventListener('abort', function () {
      fail('Upload cancelled.');
    });

    xhr.send(payload);
  }

  input.addEventListener('change', check);
  form.addEventListener('submit', function (e) {
    if (uploading) {
      e.preventDefault();
      return;
    }
    if (!check()) {
      e.preventDefault();
      return;
    }
    // Without XHR/FormData the form keeps its classic POST fallback.
    if (!window.XMLHttpRequest || !window.FormData) return;
    e.preventDefault();
    start();
  });
});
