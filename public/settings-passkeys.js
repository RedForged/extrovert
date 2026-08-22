// Page glue for Settings → Security "Add a passkey".
(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', function () {
    const btn = document.getElementById('passkey-add');
    const status = document.getElementById('passkey-status');
    if (!btn || !window.ExtrovertPasskeys) return;

    btn.addEventListener('click', async function () {
      btn.disabled = true;
      status.textContent = 'Waiting for your authenticator…';
      try {
        const label = window.prompt('Name this passkey (e.g. "YubiKey 5C", "This laptop"):');
        if (label === null) {
          btn.disabled = false;
          status.textContent = '';
          return;
        }
        await window.ExtrovertPasskeys.register(label, status);
      } catch (err) {
        status.textContent = err.name === 'NotAllowedError'
          ? 'Passkey creation cancelled or timed out.'
          : (err.message || 'Passkey creation failed.');
        btn.disabled = false;
      }
    });
  });
})();
