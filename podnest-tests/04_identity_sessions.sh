#!/usr/bin/env bash
# Items 9, 10, 27 — identity characters, session timestamps, scoped hashes. (PodNest edition)
source "$(dirname "$0")/lib.sh"

banner "Item 9: lookalike / hidden characters in a privileged login"
ID_CYR="$(ensure_user musv_cyr administrator)"
# Cyrillic small a (U+0430, bytes D0 B0) + 'dmin_musv'
set_user_login "${ID_CYR}" $'\xd0\xb0dmin_musv'
expect "identity: high 'hidden or lookalike characters' for the Cyrillic-a admin login"

ID_WS="$(ensure_user musv_ws administrator)"
set_user_login "${ID_WS}" 'musv_ws '
expect "identity: high 'hidden or lookalike characters' for the trailing-space admin login"

banner "Item 10: session expiry beyond max + future login time"
ID_SESS="$(ensure_user musv_sess administrator)"
WP eval "\$m = WP_Session_Tokens::get_instance( ${ID_SESS} ); \$m->create( time() + DAY_IN_SECONDS );" >/dev/null
WP eval "\$t = get_user_meta( ${ID_SESS}, 'session_tokens', true ); if ( is_array( \$t ) && \$t ) { \$k = array_key_first( \$t ); \$t[ \$k ]['expiration'] = time() + 60 * DAY_IN_SECONDS; \$t[ \$k ]['login'] = time() + 3 * DAY_IN_SECONDS; update_user_meta( ${ID_SESS}, 'session_tokens', \$t ); }" >/dev/null
expect "sessions: high 'Session expires far beyond the WordPress maximum' AND high 'Session login time is in the future' for musv_sess"

banner "Item 27: scoped password-hash reads (multisite subsite scan)"
expect "on a subsite scan, password-hash findings appear only for that site's members (verify with a subsite --url)"

echo ""
echo "Done."
