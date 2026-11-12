#!/usr/bin/env bash
# Items 1+4, 8, 21 — effective privileges resolved like core.
source "$(dirname "$0")/lib.sh"

banner "Item 1+4: role key with a false value (hidden admin)"
ID_FALSE="$(ensure_user musv_false subscriber)"
# administrator role key present but false -> core still grants the role
set_raw_caps "${ID_FALSE}" 'a:1:{s:13:"administrator";b:0;}'
expect "inventory shows 'administrator' for musv_false; effective privileges treats it as an admin"

banner "Item 1+4: direct false overrides a role grant"
ID_OVERRIDE="$(ensure_user musv_override editor)"
set_raw_caps "${ID_OVERRIDE}" 'a:2:{s:13:"administrator";b:1;s:14:"manage_options";b:0;}'
expect "musv_override effective caps do NOT include manage_options"

banner "Item 1+4: duplicate capability rows (first umeta_id wins)"
ID_DUP="$(ensure_user musv_dup subscriber)"
set_raw_caps "${ID_DUP}" 'a:1:{s:10:"subscriber";b:1;}'
# second row, higher umeta_id, grants administrator — must be ignored for access
${WP} db query "INSERT INTO ${PREFIX}usermeta (user_id, meta_key, meta_value) VALUES (${ID_DUP}, '${PREFIX}capabilities', 'a:1:{s:13:\"administrator\";b:1;}')"
expect "metadata test: 'duplicate capability rows' for musv_dup; the 2nd row grants NO access"

banner "Item 8: unfiltered_upload is sensitive"
ID_UP="$(ensure_user musv_upload editor)"
set_raw_caps "${ID_UP}" 'a:2:{s:6:"editor";b:1;s:17:"unfiltered_upload";b:1;}'
expect "privileges: direct sensitive grant (unfiltered_upload) for musv_upload"
expect "admins get NO runtime-denied finding for unfiltered_upload unless ALLOW_UNFILTERED_UPLOADS is set"

banner "Item 21: user_level does not match role"
ID_LVL="$(ensure_user musv_level subscriber)"
${WP} user meta update "${ID_LVL}" "${PREFIX}user_level" 10 >/dev/null
expect "metadata: high-severity 'user level does not match the assigned role' (stored 10 vs level 0) for musv_level"

echo ""
echo "Done. Run a site scan and check the findings above."
