#!/usr/bin/env bash
# Item 6 / 12 (checksums) — only meaningful on a RELEASE-ZIP install that shipped
# checksums.sha256. On a git/dev install there is no such file and the plugin's
# own files are scanned (reported as informational code paths). (PodNest edition)
source "$(dirname "$0")/lib.sh"

MUSV_DIR="${PLUGIN_DIR}/mode-user-security-validation"

if ! runsh "test -f '${MUSV_DIR}/checksums.sha256'" 2>/dev/null; then
    echo "No checksums.sha256 in the plugin — this is a dev/git install."
    expect "the plugin's own files appear as informational 'user-management path' code paths; no checksum finding"
    exit 0
fi

banner "Item 6: tamper with an own plugin file against release checksums"
runsh "printf '\n/* MUSV TEST FIXTURE comment — flips the checksum */\n' >> '${MUSV_DIR}/includes/class-plugin.php'"
expect "code paths: high 'Plugin file does not match its release checksum' for includes/class-plugin.php"

echo ""
echo "Done."
