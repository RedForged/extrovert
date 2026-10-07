(function(){
  document.addEventListener('DOMContentLoaded', function(){
    var btns = document.querySelectorAll('.copy-ref');
    for(var i=0;i<btns.length;i++){
      btns[i].addEventListener('click', function(){
        var url = this.getAttribute('data-link');
        var btn = this;
        var label = btn.querySelector('.copy-ref-label') || btn;
        if(navigator.clipboard){
          navigator.clipboard.writeText(url).then(function(){
            var orig = label.textContent;
            label.textContent = 'Copied!';
            setTimeout(function(){label.textContent=orig},2000);
          }).catch(function(){});
        }
      });
    }
  });
})();
