#!/usr/bin/env bash
# Items 2, 3, 7, 28 — code-path pattern matching. (PodNest edition)
# Fixtures live in an ACTIVE regular plugin (mu-plugins is owned by PodNest and
# not writable). All PHP fixtures are INERT: tokens live in functions that are
# never hooked and are guarded off; they exist only to trip static matching.
source "$(dirname "$0")/lib.sh"

FIX="${PLUGIN_DIR}/musv-fixtures"

banner "Item 2/3/7/28: build the musv-fixtures plugin"
make_plugin musv-fixtures "static user-code-path fixtures" <<'PHP'
/* sibling files in this folder carry the patterns; nothing here hooks anything */
PHP

# item 2 — multiple categories in one file (hide users + hard-coded sign-in)
write_file "${FIX}/multi.php" <<'PHP'
<?php
/* MUSV TEST FIXTURE — inert. Not hooked, guarded off; only here to be scanned. */
if ( false ) {
    add_filter( 'pre_user_query', 'musv_fixture_noop' );
    if ( isset( $_GET['musv'] ) && $_GET['musv'] === 'go' ) {
        wp_set_auth_cookie( 1 );
    }
}
PHP
expect "code paths: medium 'modify user-query visibility' AND critical 'hard-coded identity' for musv-fixtures/multi.php"

# item 7 — rest_user_query + pre_count_users
write_file "${FIX}/filters.php" <<'PHP'
<?php
/* MUSV TEST FIXTURE — inert. */
if ( false ) {
    add_filter( 'rest_user_query', 'musv_fixture_noop' );
    add_filter( 'pre_count_users', 'musv_fixture_noop' );
}
PHP
expect "code paths matches rest_user_query + pre_count_users; visibility lists user-list filters active"

# item 28 — whole-word matching (must NOT match)
write_file "${FIX}/nomatch.php" <<'PHP'
<?php
/* MUSV TEST FIXTURE — these longer names must NOT match add_cap / set_role. */
function musv_fixture_add_capability() {}
function musv_fixture_reset_role() {}
PHP
expect "musv-fixtures/nomatch.php is NOT reported (add_capability/reset_role are not add_cap/set_role)"

# item 3 — hide a user row by login text, plus count rewrite
write_file "${FIX}/hide.js" <<'JS'
// MUSV TEST FIXTURE — visual row hide on users.php, inert elsewhere.
jQuery( function ( $ ) {
    if ( ! /users\.php/.test( location.pathname ) ) { return; }
    $( '#the-list tr:contains("musv_false")' ).hide();
    $( '.subsubsub .administrator .count' ).text( '(1)' );
} );
JS
expect "code paths: high 'may hide users' for hide.js; a targeted-user finding for musv_false; count-rewrite matched"

activate_plugin musv-fixtures

echo ""
echo "Done. musv-fixtures is active and will be scanned. Run a scan after the batch."
