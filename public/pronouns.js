document.addEventListener('DOMContentLoaded', function () {
  var wrap = document.getElementById('pronounRows');
  var addBtn = document.getElementById('pronounAdd');
  if (!wrap || !addBtn) return;

  var max = parseInt(wrap.getAttribute('data-max'), 10) || 6;

  function rows() { return wrap.querySelectorAll('.pronoun-row'); }

  function sync() {
    var list = rows();
    addBtn.disabled = list.length >= max;
    Array.prototype.forEach.call(list, function (row) {
      var btn = row.querySelector('.pronoun-remove');
      if (btn) btn.hidden = list.length <= 2;
    });
  }

  addBtn.addEventListener('click', function () {
    var list = rows();
    if (list.length >= max) return;
    var row = list[0].cloneNode(true);
    var input = row.querySelector('input');
    input.value = '';
    input.setAttribute('aria-label', 'Pronouns field ' + (list.length + 1));
    wrap.appendChild(row);
    input.focus();
    sync();
  });

  wrap.addEventListener('click', function (e) {
    var btn = e.target && e.target.closest ? e.target.closest('.pronoun-remove') : null;
    if (!btn || rows().length <= 2) return;
    btn.closest('.pronoun-row').remove();
    sync();
  });

  sync();
});
