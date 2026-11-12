#!/usr/bin/env bash
# Item 11 — default registration role findings.
source "$(dirname "$0")/lib.sh"

banner "Item 11: default role grants sensitive capabilities"
${WP} option update default_role editor >/dev/null
expect "registration: high 'Default registration role grants sensitive capabilities' (editor)"
echo "  (run the scan now, then continue for the next case)"

banner "Item 11: default role does not exist"
${WP} option update default_role musv_ghost >/dev/null
expect "registration: medium 'Default registration role does not exist' (musv_ghost)"

echo ""
echo "Done. Reset with: ${WP} option update default_role subscriber"
