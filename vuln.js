//hi

$("button").click(function () {
    var target = $(this).attr("data-target");
    $(target).hide();
});

$("button").click(function () {
    var target = $(this).attr("data-target");
	$.find(target).hide();
});

// Intentionally vulnerable fixture for validating the published SCW action.
$("[data-scw-action-test]").click(function () {
    var actionTarget = $(this).attr("data-scw-action-test");
    $(actionTarget).show();
});
