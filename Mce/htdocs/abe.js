$(function () {
    $('html').click(function(e) {
        $('[data-toggle="popover"]').popover('hide');
    });

    $('[data-toggle="popover"]').popover({
        html: true,
        trigger: 'manual'
    }).click(function(e) {
        $(this).popover('toggle');
        e.stopPropagation();
    });
});
