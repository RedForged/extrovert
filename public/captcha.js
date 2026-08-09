// Register-page captcha helper: "new characters" button.
// The captcha image is served by GET /register/captcha (session-bound, no
// caching); refreshing just busts the cache and re-loads it, which generates a
// brand-new challenge on the server. No solver logic lives client-side — the
// whole point is that only a human can read the image.
(function () {
  'use strict';

  function init() {
    var img = document.getElementById('captcha-img');
    var btn = document.getElementById('captcha-refresh');
    if (!img || !btn) return;
    btn.addEventListener('click', function () {
      var wasFocused = document.activeElement === btn;
      img.src = '/register/captcha?v=' + Date.now();
      var input = document.getElementById('captcha-input');
      if (input) { input.value = ''; input.focus(); }
      else if (wasFocused) btn.blur();
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
