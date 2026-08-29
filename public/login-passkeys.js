// Page glue for the login page's "Sign in with a passkey" control.
//
// The control is a server-rendered <a> element in a card BELOW the login form
// (see src/views/login.ejs). It is NOT injected into the DOM at runtime: any
// post-load DOM mutation makes password managers (Proton Pass and friends) that
// observe the page re-classify it, and a second interactive control then makes
// them fill the username but skip the password. Because the anchor is in the
// initial HTML and is a link (not a <button>), the page presents exactly one
// button — the form's submit — exactly like the pre-passkey page where autofill
// worked.
(function () {
  'use strict';

  function mount() {
    const link = document.getElementById('passkey-login');
    const status = document.getElementById('passkey-status');
    if (!link || !window.ExtrovertPasskeys) return;

    link.addEventListener('click', async function (ev) {
      ev.preventDefault();
      link.classList.add('disabled');
      link.setAttribute('aria-disabled', 'true');
      if (status) status.textContent = 'Waiting for your authenticator…';
      try {
        // Username field is optional: when empty, the discoverable-credential
        // flow lets the authenticator pick the passkey.
        await window.ExtrovertPasskeys.authenticate(
          document.getElementById('login-username') ? document.getElementById('login-username').value.trim() : ''
        );
      } catch (err) {
        if (status) {
          status.textContent = err.name === 'NotAllowedError'
            ? 'Passkey sign-in cancelled or timed out.'
            : (err.message || 'Passkey sign-in failed.');
        }
        link.classList.remove('disabled');
        link.removeAttribute('aria-disabled');
      }
    });
  }

  // The control is already present in the initial HTML, so attach the handler
  // as soon as the DOM is parsed (defer runs after parse). No waiting for a
  // "settle margin" — nothing is injected later, so nothing re-triggers a
  // manager's classification pass.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mount, { once: true });
  } else {
    mount();
  }
})();
