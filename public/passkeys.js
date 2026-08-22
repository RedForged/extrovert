// Passkey ceremonies for the browser (WebAuthn). CSP forbids inline scripts,
// so all logic lives here. Mirrors public/push-register.js conventions:
// CSRF token from <meta name="csrf-token">, JSON fetches with X-CSRF-Token.
(function () {
  'use strict';

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  function post(url, body) {
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
      credentials: 'include',
      body: JSON.stringify(body || {}),
    }).then(async (res) => {
      let data = null;
      try { data = await res.json(); } catch {}
      if (!res.ok) {
        const msg = data && data.error && data.error.message ? data.error.message : 'Request failed (' + res.status + ')';
        throw new Error(msg);
      }
      return data;
    });
  }

  function setStatus(el, text, isError) {
    if (!el) return;
    el.textContent = text;
    el.classList.toggle('err', !!isError);
  }

  // ---- base64url <-> ArrayBuffer helpers (browser WebAuthn uses ArrayBuffers) ----
  function b64uToBuf(b64u) {
    const pad = '='.repeat((4 - (b64u.length % 4)) % 4);
    const b64 = b64u.replace(/-/g, '+').replace(/_/g, '/') + pad;
    const bin = atob(b64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }

  function bufToB64u(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function prepareCreateOptions(options) {
    options.challenge = b64uToBuf(options.challenge);
    if (options.user && options.user.id) options.user.id = b64uToBuf(options.user.id);
    (options.excludeCredentials || []).forEach((c) => { c.id = b64uToBuf(c.id); });
    return options;
  }

  function prepareGetOptions(options) {
    options.challenge = b64uToBuf(options.challenge);
    (options.allowCredentials || []).forEach((c) => { c.id = b64uToBuf(c.id); });
    return options;
  }

  // Registration: create a credential on the authenticator and enroll it.
  async function register(label, statusEl) {
    if (!window.PublicKeyCredential) throw new Error('This browser does not support passkeys.');
    const options = prepareCreateOptions(await post('/passkeys/register/begin', {}));
    options.rp = options.rp || {};
    const credential = await navigator.credentials.create({ publicKey: options });
    const body = {
      id: credential.id,
      rawId: bufToB64u(credential.rawId),
      type: credential.type,
      label: label || undefined,
      transports: credential.response.getTransports ? credential.response.getTransports() : undefined,
      response: {
        clientDataJSON: bufToB64u(credential.response.clientDataJSON),
        attestationObject: bufToB64u(credential.response.attestationObject),
        publicKeyAlgorithm: credential.response.getPublicKeyAlgorithm
          ? credential.response.getPublicKeyAlgorithm() : undefined,
        publicKey: credential.response.getPublicKey
          ? bufToB64u(credential.response.getPublicKey()) : undefined,
        authenticatorData: undefined,
      },
    };
    if (credential.response.getAuthenticatorData) {
      body.response.authenticatorData = bufToB64u(credential.response.getAuthenticatorData());
    }
    const result = await post('/passkeys/register/complete', body);
    setStatus(statusEl, 'Passkey "' + (result.device_name || label || 'new') + '" added.', false);
    setTimeout(() => window.location.reload(), 600);
  }

  // Authentication: discoverable-credential flow when username is omitted.
  async function authenticate(username, statusEl) {
    if (!window.PublicKeyCredential) throw new Error('This browser does not support passkeys.');
    const options = prepareGetOptions(await post('/passkeys/auth/options', { username: username || '' }));
    const assertion = await navigator.credentials.get({ publicKey: options });
    await post('/passkeys/auth/verify', {
      id: assertion.id,
      rawId: bufToB64u(assertion.rawId),
      type: assertion.type,
      response: {
        clientDataJSON: bufToB64u(assertion.response.clientDataJSON),
        authenticatorData: bufToB64u(assertion.response.authenticatorData),
        signature: bufToB64u(assertion.response.signature),
        userHandle: assertion.response.userHandle ? bufToB64u(assertion.response.userHandle) : null,
      },
    });
    window.location.href = '/';
  }

  window.ExtrovertPasskeys = { register, authenticate };
})();
