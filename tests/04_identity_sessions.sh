#!/usr/bin/env bash
# Items 9, 10, 27 — identity characters, session timestamps, scoped hashes.
source "$(dirname "$0")/lib.sh"

banner "Item 9: lookalike / hidden characters in a privileged login"
ID_CYR="$(ensure_user musv_cyr administrator)"
# replace the 'a' with a Cyrillic U+0430; privileged account with a lookalike login
${WP} db query "UPDATE ${PREFIX}users SET user_login=CONCAT(CHAR(0xD0 USING utf8mb4), CHAR(0xB0 USING utf8mb4), 'dmin_musv') WHERE ID=${ID_CYR}"
expect "identity: high 'hidden or lookalike characters' for the Cyrillic-a admin login"

ID_WS="$(ensure_user musv_ws administrator)"
${WP} db query "UPDATE ${PREFIX}users SET user_login='musv_ws ' WHERE ID=${ID_WS}"
expect "identity: high 'hidden or lookalike characters' for the trailing-space admin login"

banner "Item 10: session expiry beyond max + future login time"
ID_SESS="$(ensure_user musv_sess administrator)"
# seed one real session, then push its expiration and login time out
${WP} eval "wp_set_password( 'musv-temp-pass', ${ID_SESS} );" >/dev/null
${WP} eval '
$m = WP_Session_Tokens::get_instance( '"${ID_SESS}"' );
$m->create( time() + DAY_IN_SECONDS );
$t = get_user_meta( '"${ID_SESS}"', "session_tokens", true );
if ( is_array( $t ) && $t ) {
    $k = array_key_first( $t );
    $t[ $k ]["expiration"] = time() + 60 * DAY_IN_SECONDS;
    $t[ $k ]["login"]      = time() + 3 * DAY_IN_SECONDS;
    update_user_meta( '"${ID_SESS}"', "session_tokens", $t );
}
' >/dev/null
expect "sessions: high 'Session expires far beyond the WordPress maximum' AND high 'Session login time is in the future' for musv_sess"

banner "Item 27: scoped password-hash reads (multisite subsite scan)"
expect "on a subsite scan, password-hash findings appear only for that site's members (verify with ${URL_ARG:-a subsite --url})"

echo ""
echo "Done."
