#!/usr/bin/env bash
# Items 18, 19, 20, 26, 33 — Users-screen simulation and browser-side behavior.
source "$(dirname "$0")/lib.sh"

banner "Item 20: pre_user_query that only fires on the Users screen path"
cat > "${MU_DIR}/musv-fixture-screen-hide.php" <<'PHP'
<?php
/* MUSV TEST FIXTURE — hides musv_false only when the request URI looks like users.php.
   Active (not guarded) so the simulated Users screen triggers it. Harmless: it only
   filters an admin-side user query on a disposable site. */
add_action( 'pre_user_query', function ( $q ) {
    $uri  = $_SERVER['REQUEST_URI'] ?? '';
    $self = $_SERVER['PHP_SELF'] ?? '';
    if ( false === strpos( $uri, 'users.php' ) && false === strpos( $self, 'users.php' ) ) {
        return;
    }
    global $wpdb;
    $q->query_where .= " AND {$wpdb->users}.user_login <> 'musv_false'";
} );
PHP
expect "visibility: 'Users screen hides a database user' for musv_false (REQUEST_URI/PHP_SELF simulated)"

banner "Item 19: AJAX handler returns non-JSON"
cat > "${MU_DIR}/musv-fixture-bad-ajax.php" <<'PHP'
<?php
/* MUSV TEST FIXTURE — makes the scan request return a non-JSON body. */
add_action( 'wp_ajax_mode_usv_run_test', function () { echo 'oops'; exit; }, 0 );
PHP
expect "UI: 'The test request failed... (HTTP 200)' — NOT a raw SyntaxError"
echo "  NOTE: this breaks every scan while active. Deactivate it before the other UI tests:"
echo "    rm ${MU_DIR}/musv-fixture-bad-ajax.php"

banner "Item 18: cancel during code-path batches"
expect "generate many files (03_files_folders.sh item 16), start a scan, click Cancel mid code-path: that test shows Cancelled, not Complete"

banner "Item 26: privileged_users counts beyond the 5,000 display cap"
echo "  Generating 5,100 users (slow)..."
${WP} user generate --count=5100 --role=subscriber >/dev/null
LAST_ID="$(${WP} user list --role=subscriber --field=ID --orderby=ID --order=DESC --number=1)"
set_raw_caps "${LAST_ID}" 'a:1:{s:13:"administrator";b:1;}'
expect "inventory metric privileged_users counts user ID ${LAST_ID} even though it is past the 5,000th display row"

banner "Item 33: one inventory row per user for network-wide findings (multisite)"
expect "on a network scan, a user on two sites with a network-wide finding appears ONCE in Users With Issues and once in downloaded users[]"

echo ""
echo "Done."
