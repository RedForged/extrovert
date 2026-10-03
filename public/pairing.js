'use strict';

document.addEventListener('DOMContentLoaded', () => {
  const initBtn = document.getElementById('init-pair-btn');
  const resultDiv = document.getElementById('pair-result');
  const codeEl = document.getElementById('pair-code');
  const qrImg = document.getElementById('pair-qr-img');
  const urlInput = document.getElementById('pair-url');
  const copyBtn = document.getElementById('copy-url-btn');
  const timerEl = document.getElementById('pair-timer');
  let countdownTimer = null;

  if (copyBtn && urlInput) {
    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(urlInput.value);
        const originalText = copyBtn.innerHTML;
        copyBtn.textContent = 'Copied!';
        setTimeout(() => { copyBtn.innerHTML = originalText; }, 2000);
      } catch (err) {
        urlInput.select();
        document.execCommand('copy');
      }
    });
  }

  if (initBtn) {
    initBtn.addEventListener('click', async () => {
      initBtn.disabled = true;
      initBtn.textContent = 'Generating...';

      try {
        const csrfMeta = document.querySelector('meta[name="csrf-token"]');
        const csrfToken = csrfMeta ? csrfMeta.content : '';

        const res = await fetch('/api/v1/auth/pair/init', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken,
          },
          credentials: 'same-origin',
        });

        const json = await res.json();
        if (!res.ok) {
          throw new Error(json.error_description || json.message || 'Failed to initialize pairing');
        }

        const data = json.data || {};
        codeEl.textContent = data.code || '';
        urlInput.value = data.pairing_url || '';

        if (data.pairing_url) {
          qrImg.src = '/settings/devices/qr?url=' + encodeURIComponent(data.pairing_url);
        }

        resultDiv.style.display = 'block';

        if (countdownTimer) clearInterval(countdownTimer);
        let seconds = data.expires_in || 300;
        timerEl.textContent = String(seconds);

        countdownTimer = setInterval(() => {
          seconds -= 1;
          if (seconds <= 0) {
            clearInterval(countdownTimer);
            timerEl.textContent = 'Expired';
            initBtn.disabled = false;
            initBtn.textContent = 'Generate pairing code';
          } else {
            timerEl.textContent = String(seconds);
          }
        }, 1000);

      } catch (err) {
        alert(err.message);
      } finally {
        initBtn.disabled = false;
        initBtn.textContent = 'Generate new pairing code';
      }
    });
  }
});
