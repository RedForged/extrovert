(function () {
  'use strict';

  // Sealed chat attachments: the browser encrypts the file with a fresh
  // AES-256-GCM key before it ever leaves the machine. The key and IV travel
  // inside the end-to-end encrypted message, so the server only ever holds an
  // unreadable blob and never learns the file's name or type.
  var PREFIX = '\u0001ev-file:';

  function toB64(buf) {
    var bytes = new Uint8Array(buf);
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  function fromB64(str) {
    var bin = atob(str);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function seal(file) {
    if (!window.crypto || !window.crypto.subtle) {
      return Promise.reject(new Error('WebCrypto unavailable'));
    }
    var key = window.crypto.getRandomValues(new Uint8Array(32));
    var iv = window.crypto.getRandomValues(new Uint8Array(12));
    // WebCrypto needs bytes, not a Blob/File.
    return file.arrayBuffer()
      .then(function (plain) {
        return window.crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt'])
          .then(function (k) {
            return window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, k, plain);
          });
      })
      .then(function (cipher) {
        return {
          blob: new Blob([cipher], { type: 'application/octet-stream' }),
          key: toB64(key),
          iv: toB64(iv),
          size: cipher.byteLength,
        };
      });
  }

  function open(url, keyB64, ivB64, mime) {
    return fetch(url, { credentials: 'same-origin' })
      .then(function (r) {
        if (!r.ok) throw new Error('attachment fetch failed: ' + r.status);
        return r.arrayBuffer();
      })
      .then(function (buf) {
        return window.crypto.subtle.importKey('raw', fromB64(keyB64), { name: 'AES-GCM' }, false, ['decrypt'])
          .then(function (k) {
            return window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(ivB64) }, k, buf);
          });
      })
      .then(function (plain) {
        return new Blob([plain], { type: mime || 'application/octet-stream' });
      });
  }

  function envelope(info) {
    return PREFIX + JSON.stringify({
      v: 1,
      u: info.u,
      k: info.k,
      i: info.i,
      n: info.n || '',
      m: info.m || 'application/octet-stream',
      s: info.s || 0,
      t: info.t || '',
    });
  }

  function parse(text) {
    if (typeof text !== 'string' || text.indexOf(PREFIX) !== 0) return null;
    try {
      var o = JSON.parse(text.slice(PREFIX.length));
      return o && o.v === 1 && o.u && o.k && o.i ? o : null;
    } catch (e) {
      return null;
    }
  }

  // Renders decrypted plaintext into an element: a sealed attachment, a sticker
  // path, or plain text. Shared by the DM and room clients.
  function humanSize(bytes) {
    var n = Number(bytes) || 0;
    if (n >= 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB';
    if (n >= 1024) return Math.round(n / 1024) + ' KB';
    return n + ' B';
  }

  function escapeHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function render(el, plaintext) {
    if (!el) return;
    var env = parse(plaintext);

    if (!env) {
      if (plaintext && plaintext.indexOf('/uploads/stickers/') === 0) {
        el.innerHTML = '<img src="' + escapeHtml(plaintext) + '" class="sticker-inline" style="max-width:120px;max-height:120px;vertical-align:middle" alt="sticker">';
        return;
      }
      el.textContent = plaintext;
      return;
    }

    el.textContent = '';
    if (env.t) {
      var cap = document.createElement('div');
      cap.className = 'att-caption';
      cap.textContent = env.t;
      el.appendChild(cap);
    }
    var holder = document.createElement('div');
    holder.className = 'att-file';
    holder.textContent = 'Decrypting…';
    el.appendChild(holder);

    var mime = String(env.m || '');
    open(env.u, env.k, env.i, mime).then(function (blob) {
      var url = URL.createObjectURL(blob);
      holder.textContent = '';
      if (mime.indexOf('image/') === 0) {
        var img = document.createElement('img');
        img.className = 'att-media';
        img.src = url;
        img.alt = env.n || 'attachment';
        img.title = env.n || '';
        holder.appendChild(img);
      } else if (mime.indexOf('video/') === 0) {
        var vid = document.createElement('video');
        vid.className = 'att-media';
        vid.controls = true;
        vid.src = url;
        holder.appendChild(vid);
      } else {
        var a = document.createElement('a');
        a.className = 'btn ghost small att-download';
        a.href = url;
        a.download = env.n || 'attachment';
        a.textContent = (env.n || 'File') + ' · ' + humanSize(env.s || blob.size);
        holder.appendChild(a);
      }
    }).catch(function () {
      holder.textContent = 'Could not open attachment.';
    });
  }

  window.ExtrovertFiles = { seal: seal, open: open, envelope: envelope, parse: parse, render: render, humanSize: humanSize, prefix: PREFIX };
})();
