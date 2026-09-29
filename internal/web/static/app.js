// Progressive enhancement only; every action works without this file.
(function () {
  // Confirm dangerous forms.
  document.addEventListener('submit', function (e) {
    var form = e.target;
    if (form.dataset && form.dataset.confirm && !window.confirm(form.dataset.confirm)) {
      e.preventDefault();
    }
  });

  // Revealed secrets hide themselves again and offer a copy button.
  function arm(el) {
    var box = el.querySelector('.secret');
    if (!box) return;
    var seconds = parseInt(box.dataset.expires || '30', 10);
    var cd = box.querySelector('.countdown');
    var timer = setInterval(function () {
      seconds -= 1;
      if (cd) cd.textContent = String(seconds);
      if (seconds <= 0) {
        clearInterval(timer);
        el.innerHTML = '';
      }
    }, 1000);
    var copy = box.querySelector('.copy');
    if (copy && navigator.clipboard) {
      copy.addEventListener('click', function () {
        navigator.clipboard.writeText(box.querySelector('.value').textContent).then(function () {
          copy.textContent = 'Copied';
          setTimeout(function () { copy.textContent = 'Copy'; }, 1500);
        });
      });
    } else if (copy) {
      copy.remove();
    }
  }
  document.body.addEventListener('htmx:afterSwap', function (e) {
    if (e.target && e.target.classList.contains('reveal')) arm(e.target);
  });

  // Show the size/curve field that matches the chosen key type.
  var kind = document.getElementById('kind');
  if (kind) {
    var bits = document.querySelector('input[name=bits]');
    var curve = document.querySelector('select[name=curve]');
    var update = function () {
      var k = kind.value;
      bits.closest('label').style.display = (k === 'rsa' || k === 'oct') ? '' : 'none';
      curve.closest('label').style.display = k === 'ec' ? '' : 'none';
      bits.placeholder = k === 'rsa' ? '3072' : k === 'oct' ? '256' : '';
    };
    kind.addEventListener('change', update);
    update();
  }
})();
