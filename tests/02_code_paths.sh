#!/usr/bin/env bash
# Items 2, 3, 7, 28 — code-path pattern matching.
# All PHP fixtures are INERT: the matched tokens live in functions that are
# never hooked and are guarded so they cannot run. They exist only to trip
# the scanner's static string/regex matching.
source "$(dirname "$0")/lib.sh"

banner "Item 2: multiple categories in one file (hide users + hard-coded sign-in)"
cat > "${MU_DIR}/musv-fixture-multi.php" <<'PHP'
<?php
/* MUSV TEST FIXTURE — inert. Not hooked, guarded off; only here to be scanned. */
if ( false ) {
    add_filter( 'pre_user_query', 'musv_fixture_noop' );
    if ( isset( $_GET['musv'] ) && $_GET['musv'] === 'go' ) {
        wp_set_auth_cookie( 1 );
    }
}
PHP
expect "code paths: a medium 'modify user-query visibility' AND a critical 'hard-coded identity' for musv-fixture-multi.php"

banner "Item 3: hide a user row by login text, plus count rewrite"
mkdir -p "${PLUGIN_DIR}/musv-fixture-hide"
cat > "${PLUGIN_DIR}/musv-fixture-hide/hide.js" <<'JS'
// MUSV TEST FIXTURE — visual row hide on users.php, inert elsewhere.
jQuery( function ( $ ) {
    if ( ! /users\.php/.test( location.pathname ) ) { return; }
    $( '#the-list tr:contains("musv_false")' ).hide();
    $( '.subsubsub .administrator .count' ).text( '(1)' );
} );
JS
expect "code paths: high 'may hide users' for hide.js; a targeted-user finding for musv_false; users_screen_count_rewrite matched"

banner "Item 7: rest_user_query + pre_count_users filters"
cat > "${MU_DIR}/musv-fixture-filters.php" <<'PHP'
<?php
/* MUSV TEST FIXTURE — inert. */
if ( false ) {
    add_filter( 'rest_user_query', 'musv_fixture_noop' );
    add_filter( 'pre_count_users', 'musv_fixture_noop' );
}
PHP
expect "code paths matches rest_user_query + pre_count_users; visibility lists user-list filters active"

banner "Item 28: whole-word matching (should NOT match)"
cat > "${MU_DIR}/musv-fixture-nomatch.php" <<'PHP'
<?php
/* MUSV TEST FIXTURE — these longer names must NOT match add_cap / set_role. */
function musv_fixture_add_capability() {}
function musv_fixture_reset_role() {}
PHP
expect "musv-fixture-nomatch.php is NOT reported (add_capability/reset_role are not add_cap/set_role)"

echo ""
echo "Done. Activate the musv-fixture-hide plugin (wp plugin activate musv-fixture-hide) then run a scan."
