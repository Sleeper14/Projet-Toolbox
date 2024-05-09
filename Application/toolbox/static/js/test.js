$(window).on('load', function() {
    $('#js-preloader').fadeOut('slow');
});

window.sr = ScrollReveal();
sr.reveal('.some-class', {
    duration: 1000,
    origin: 'bottom',
    distance: '50px'
});

$(document).on('click', 'a[href^="#"]', function(event) {
    event.preventDefault();
    var target = $(this.getAttribute('href'));
    if (target.length) {
        $('html, body').stop().animate({
            scrollTop: target.offset().top
        }, 1000);
    }
});
