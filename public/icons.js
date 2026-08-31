// Shared inline-SVG icon helper for client-side DOM building.
// Mirrors src/views/partials/icon.ejs (24x24 viewBox, stroke, currentColor) so
// dynamically created UI matches server-rendered markup. Extend both maps in
// lock-step when adding icons.
(function () {
  'use strict';

  var PATHS = {
    heart: '<path d="M12 20s-7-4.5-7-10a4 4 0 0 1 7-2.5A4 4 0 0 1 19 10c0 5.5-7 10-7 10Z"/>',
    heartFilled: '<path d="M12 20s-7-4.5-7-10a4 4 0 0 1 7-2.5A4 4 0 0 1 19 10c0 5.5-7 10-7 10Z" fill="currentColor" stroke="none"/>',
    comment: '<path d="M4 5h16v11H8l-4 4V5Z"/>',
    share: '<path d="M4 12 20 4l-4 16-4-7-8-1Z"/>',
    more: '<circle cx="5" cy="12" r="1.6" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.6" fill="currentColor" stroke="none"/><circle cx="19" cy="12" r="1.6" fill="currentColor" stroke="none"/>',
    check: '<path d="M4 12l5 5L20 6"/>',
    speaker: '<path d="M11 5 6.5 9H3v6h3.5L11 19V5Z"/><path d="M15.5 8.5a5 5 0 0 1 0 7"/><path d="M18.5 6a9 9 0 0 1 0 12"/>',
    phoneIncoming: '<path d="M5 4h4l2 5-3 2a12 12 0 0 0 5 5l2-3 5 2v4a2 2 0 0 1-2 2A16 16 0 0 1 3 6a2 2 0 0 1 2-2Z"/><path d="M16 3l-5 5"/><path d="M11 3v5h5"/>',
  };

  /**
   * Build an inline SVG element matching the server-rendered icon partial.
   * @param {string} name key in PATHS
   * @param {number} [size=16]
   * @param {string} [cls] optional class for the <svg>
   * @returns {SVGElement}
   */
  function icon(name, size, cls) {
    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', size || 16);
    svg.setAttribute('height', size || 16);
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    if (cls) svg.setAttribute('class', cls);
    var wrap = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    wrap.innerHTML = PATHS[name] || '';
    while (wrap.firstChild) svg.appendChild(wrap.firstChild);
    return svg;
  }

  window.DSHIcons = { icon: icon, PATHS: PATHS };
})();
