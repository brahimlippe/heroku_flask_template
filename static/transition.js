window.transitionToPage = function (href) {
    document.querySelector('body').style.animation = "fadeOut 1s ease-out 0s 1 normal"
    document.querySelector('body').style.animationFillMode = "both";
    setTimeout(() =>  window.location.href = href, 750)
}