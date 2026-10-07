(function () {
  'use strict';

  var page = document.querySelector('[data-profile-effect]');
  if (!page) return;
  var effect = page.getAttribute('data-profile-effect');
  if (effect !== 'matrix' && effect !== 'glitch') return;
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  // Watchdog only. The effect really ends when the rain has drained, so this
  // only fires if something pathological stops that from happening.
  var MAX_MS = 3200;
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

  // Fade out on a clock, then clean up once the fade has finished.
  function blendOut(ms) {
    setTimeout(function () {
      nodes.forEach(function (n) { n.classList.remove('pfx-in'); });
      setTimeout(cleanup, 240);
    }, ms);
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
    var CELLS_PER_SEC = 60;
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    var cols = Math.ceil(canvas.width / size) + 1;
    var drops = [];
    for (var c = 0; c < cols; c++) drops.push(Math.random() * -(canvas.height / size));

    var start = Date.now();
    var last = start;
    // Rain until drainAt, then stop spawning and let the glyphs run off the
    // bottom of the screen — at the same constant speed as the rain itself.
    var drainAt = 950;
    function draw() {
      var now = Date.now();
      var t = now - start;
      // Advance by elapsed time rather than by frame. Moves are identical no
      // matter what the frame rate is doing, so the speed never changes.
      var dt = Math.min(now - last, 250);
      last = now;
      var spawning = t < drainAt;
      var step = (dt / 1000) * CELLS_PER_SEC;
      // Erase the previous frames instead of painting black over them, so the
      // rain trails stay transparent and the page keeps its own background.
      // Scaled the same way, so trail length doesn't shift with the frame rate.
      ctx.globalCompositeOperation = 'destination-out';
      ctx.fillStyle = 'rgba(0, 0, 0, ' + Math.min(0.5, 0.22 * (dt / 16.7)).toFixed(3) + ')';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.globalCompositeOperation = 'source-over';
      ctx.font = size + 'px monospace';
      ctx.shadowColor = 'rgba(47, 220, 134, 0.7)';
      ctx.shadowBlur = 4;
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
        drops[i] += step;
      }
      ctx.shadowBlur = 0;
      // Every glyph has left the screen and the canvas has just been cleared, so
      // there is nothing left to hide: remove it here rather than on a clock,
      // which is what used to cut the rain off mid-screen.
      if (!spawning && !alive) {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        cleanup();
        return;
      }
      if (t < 3000) raf = requestAnimationFrame(draw);
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
    // Overlay only — the page content stays perfectly still. The overlay is
    // transparent once its animation is done, so it can fade on a clock.
    fadeIn(addNode(Object.assign(document.createElement('div'), { className: 'pfx-glitch-layer' })));
    blendOut(840);
  }

  try {
    if (effect === 'matrix') runMatrix();
    else runGlitch();
  } catch (e) {
    cleanup();
  }
})();
