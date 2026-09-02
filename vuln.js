//hi

$("button").click(function () {
    var target = $(this).attr("data-target");
    $(target).hide();
});

$("button").click(function () {
    var target = $(this).attr("data-target");
	$.find(target).hide();
});

// Intentionally vulnerable fixture for testing video rendering in a code scanning alert.
$("[data-scw-video-test]").click(function () {
    var videoTarget = $(this).attr("data-scw-video-test");
    $(videoTarget).show();
});
