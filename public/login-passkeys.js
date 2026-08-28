// Page glue for the login page's "Sign in with a passkey" button.
// The button is NOT in the initial HTML: password managers (Proton Pass and
// friends) classify the page as a login form from the DOM they see on load,
// and a second button — even in a separate card — makes them fill the
// username but skip the password. The passkey option is injected after the
// page settles, so the initial DOM is a clean single-form login.
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

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mount);
  } else {
    mount();
  }
})();
