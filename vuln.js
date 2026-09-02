//hi

$("button").click(function () {
    var target = $(this).attr("data-target");
    $(target).hide();
});

$("button").click(function () {
    var target = $(this).attr("data-target");
	$.find(target).hide();
});

// Intentionally vulnerable fixture for the SARIF enrichment proof.
$("[data-scw-proof]").click(function () {
    var proofTarget = $(this).attr("data-scw-proof");
    $(proofTarget).show();
});
