// Intentionally vulnerable fixture for verifying that SCW enrichment preserves
// the exact CodeQL tool identity in uploaded SARIF.
$("[data-codeql-scw-test]").click(function () {
    var identityTarget = $(this).attr("data-codeql-scw-test");
    $(identityTarget).show();
});
