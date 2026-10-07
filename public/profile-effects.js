(function () {
  'use strict';

  var page = document.querySelector('[data-profile-effect]');
  if (!page) return;
  var effect = page.getAttribute('data-profile-effect');
  if (effect !== 'matrix' && effect !== 'glitch') return;
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  // Hard cap: whatever happens, the page is restored after one second.
  var MAX_MS = 1000;
  var timer = null;
  var raf = 0;
  var nodes = [];

  function cleanup() {
    if (timer) { clearTimeout(timer); timer = null; }
    if (raf) { cancelAnimationFrame(raf); raf = 0; }
    nodes.forEach(function (n) { if (n.parentNode) n.parentNode.removeChild(n); });
    nodes = [];
    page.classList.remove('pfx-flying', 'pfx-glitching');
    Array.prototype.forEach.call(page.querySelectorAll('[style]'), function (el) {
      if (el.style.getPropertyValue('--pfx-x') || el.style.getPropertyValue('--pfx-y') || el.style.animationDelay) {
        el.style.removeProperty('--pfx-x');
        el.style.removeProperty('--pfx-y');
        el.style.removeProperty('animation-delay');
      }
    });
  }

  timer = setTimeout(cleanup, MAX_MS);

  function addNode(el) {
    el.setAttribute('aria-hidden', 'true');
    document.body.appendChild(el);
    nodes.push(el);
    return el;
  }

  function fadeIn(el) {
    requestAnimationFrame(function () { el.classList.add('pfx-in'); });
  }

  // Elements that hold text directly — the page's "text".
  function textBlocks() {
    var out = [];
    (function walk(el) {
      if (!el || out.length > 60) return;
      var hasText = false;
      for (var i = 0; i < el.childNodes.length; i++) {
        var n = el.childNodes[i];
        if (n.nodeType === 3 && n.nodeValue.replace(/\s+/g, '')) { hasText = true; break; }
      }
      if (hasText) out.push(el);
      for (var j = 0; j < el.children.length; j++) walk(el.children[j]);
    })(page);
    return out;
  }

  function runMatrix() {
    var canvas = addNode(Object.assign(document.createElement('canvas'), { className: 'pfx-canvas' }));
    fadeIn(canvas);
    var ctx = canvas.getContext('2d');
    var glyphs = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホ0123456789';
    var size = 14;
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    var cols = Math.ceil(canvas.width / size) + 1;
    var drops = [];
    for (var c = 0; c < cols; c++) drops.push(Math.random() * -(canvas.height / size));

    var start = Date.now();
    // Rain normally, then stop spawning and let every remaining glyph flow off
    // the bottom of the screen instead of having the effect cut off.
    var drainAt = 420;
    function draw() {
      var t = Date.now() - start;
      var spawning = t < drainAt;
      var speed = spawning ? 1 : 1 + Math.min(2, (t - drainAt) / 160);
      // Erase the previous frames instead of painting black over them, so the
      // rain trails stay transparent and the page keeps its own background.
      // Trails die faster once draining, so the screen really empties out.
      ctx.globalCompositeOperation = 'destination-out';
      ctx.fillStyle = spawning ? 'rgba(0, 0, 0, 0.22)' : 'rgba(0, 0, 0, 0.45)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.globalCompositeOperation = 'source-over';
      ctx.font = size + 'px monospace';
      ctx.shadowColor = 'rgba(47, 220, 134, 0.7)';
      ctx.shadowBlur = 6;
      var alive = false;
      for (var i = 0; i < cols; i++) {
        var y = drops[i] * size;
        if (y - size > canvas.height) {
          if (!spawning) continue;
          drops[i] = -Math.random() * 12;
          y = drops[i] * size;
        }
        alive = true;
        ctx.fillStyle = '#b6ffd8';
        ctx.fillText(glyphs.charAt(Math.floor(Math.random() * glyphs.length)), i * size, y - size);
        ctx.fillStyle = '#2fdc86';
        ctx.fillText(glyphs.charAt(Math.floor(Math.random() * glyphs.length)), i * size, y);
        drops[i] += speed;
      }
      ctx.shadowBlur = 0;
      // Every glyph has left the screen: nothing to fade, just clear.
      if (!spawning && !alive) {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        return;
      }
      if (t < 960) raf = requestAnimationFrame(draw);
    }
    raf = requestAnimationFrame(draw);

    // Text flies in from all four sides, staggered so the last line settles ~920ms.
    var blocks = textBlocks();
    var step = blocks.length ? Math.min(9, 260 / blocks.length) : 0;
    blocks.forEach(function (el, i) {
      var jitter = function () { return (Math.random() * 12 - 6).toFixed(1) + 'px'; };
      var edge = Math.floor(Math.random() * 4);
      if (edge === 0) {
        el.style.setProperty('--pfx-x', 'calc(-42vw + ' + jitter() + ')');
        el.style.setProperty('--pfx-y', jitter());
      } else if (edge === 1) {
        el.style.setProperty('--pfx-x', 'calc(42vw + ' + jitter() + ')');
        el.style.setProperty('--pfx-y', jitter());
      } else if (edge === 2) {
        el.style.setProperty('--pfx-x', jitter());
        el.style.setProperty('--pfx-y', 'calc(-42vh + ' + jitter() + ')');
      } else {
        el.style.setProperty('--pfx-x', jitter());
        el.style.setProperty('--pfx-y', 'calc(42vh + ' + jitter() + ')');
      }
      el.style.animationDelay = (140 + Math.round(i * step)) + 'ms';
    });
    page.classList.add('pfx-flying');
  }

  function runGlitch() {
    // Overlay only — the page content stays perfectly still.
    fadeIn(addNode(Object.assign(document.createElement('div'), { className: 'pfx-glitch-layer' })));
  }

  try {
    if (effect === 'matrix') runMatrix();
    else runGlitch();
  } catch (e) {
    cleanup();
    return;
  }

  // Blend whatever is left out, finishing exactly on the one-second mark so the
  // cleanup timer only ever removes something that is already invisible.
  setTimeout(function () {
    nodes.forEach(function (n) { n.classList.remove('pfx-in'); });
  }, 840);
})();
