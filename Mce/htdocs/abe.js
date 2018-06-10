$(function () {
    $('html').click(function(e) {
        $('[data-toggle="popover"]').popover('hide');
    });

    $('[data-toggle="popover"]').popover({
        html: true,
        trigger: 'manual'
    });
    $('[data-toggle="popover"]').not(".hover").popover().click(function(e) {
        $(this).popover('toggle');
        e.stopPropagation();
    });
    $('.hover[data-toggle="popover"]').popover().hover(function(e) {
        $(this).popover('toggle');
        e.stopPropagation();
    });
});
