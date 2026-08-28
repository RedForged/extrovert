// Page glue for the login page's "Sign in with a passkey" button.
// The button is NOT in the initial HTML: password managers (Proton Pass and
// friends) classify the page as a login form from the DOM they see on load,
// and a second button — even in a separate card — makes them fill the
// username but skip the password. The button is injected after the `load`
// event plus a settle margin, so it only shows up once the manager's
// classification pass is done. (This file runs under `defer`, so a
// readyState check can't do the deferring — see settleMount below.)
(function () {
  'use strict';

  function mount() {
    const existing = document.getElementById('passkey-login');
    if (existing || !window.ExtrovertPasskeys) return;

    const wrap = document.createElement('div');
    wrap.style.cssText = 'margin-top:16px;text-align:center';

    const status = document.createElement('div');
    status.id = 'passkey-status';
    status.className = 'muted';
    status.style.cssText = 'font-size:var(--fs-sm);margin:0 0 10px';

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.id = 'passkey-login';
    btn.className = 'btn ghost full';
    btn.textContent = ' Sign in with a passkey';
    btn.addEventListener('click', async function () {
      btn.disabled = true;
      status.textContent = 'Waiting for your authenticator…';
      try {
        // Username field is optional: when empty, the discoverable-credential
        // flow lets the authenticator pick the passkey.
        await window.ExtrovertPasskeys.authenticate(
          document.getElementById('login-username') ? document.getElementById('login-username').value.trim() : ''
        );
      } catch (err) {
        status.textContent = err.name === 'NotAllowedError'
          ? 'Passkey sign-in cancelled or timed out.'
          : (err.message || 'Passkey sign-in failed.');
        btn.disabled = false;
      }
    });

    wrap.appendChild(status);
    wrap.appendChild(btn);

    const form = document.querySelector('form[action^="/login"]');
    const anchor = form && form.parentElement ? form.parentElement.parentElement : document.body;
    anchor.appendChild(wrap);
  }

  // Inject well after the load event and password-manager scan. This file is
  // loaded with `defer`, so readyState is already 'interactive' when it runs
  // and a readyState check never defers anything (the f7b8f36 bug) — wait for
  // `load` plus a settle margin instead, so the button appears only after the
  // extension's document_idle classification pass is done.
  function settleMount() {
    if ('requestIdleCallback' in window) {
      requestIdleCallback(function () { setTimeout(mount, 2000); }, { timeout: 5000 });
    } else {
      setTimeout(mount, 2500);
    }
  }

  function scheduleMount() {
    if (document.readyState === 'complete') settleMount();
    else window.addEventListener('load', settleMount, { once: true });
  }

  scheduleMount();
})();
