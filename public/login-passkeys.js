// Page glue for the login page's "Sign in with a passkey" button.
(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', function () {
    const btn = document.getElementById('passkey-login');
    const status = document.getElementById('passkey-status');
    if (!btn || !window.ExtrovertPasskeys) return;

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
  });
})();
