#!/usr/bin/env bash
# Items 24, 32 — wpdb fallback marks the report incomplete. (PodNest edition)
# PodNest WordPress pods use a direct MariaDB connection and a Redis object-cache
# drop-in, NOT a db.php, so a normal scan uses the mysqli path. This fixture adds
# a db.php to force the fallback. wp-content is writable; the rest of the pod is not.
source "$(dirname "$0")/lib.sh"

banner "Items 24/32: db.php drop-in forces the wpdb fallback"
if runsh "test -f '${CONTENT_DIR}/db.php'" 2>/dev/null; then
    echo "  NOTE: a db.php drop-in already exists in this pod. Back it up before overwriting:"
    echo "    ${PODMAN} exec ${PHP_CT} cp ${CONTENT_DIR}/db.php ${CONTENT_DIR}/db.php.musv-bak"
fi
write_file "${CONTENT_DIR}/db.php" <<'PHP'
<?php
/* MUSV TEST FIXTURE drop-in — forces the scanner's wpdb fallback. Remove after testing. */
class MUSV_Test_DB extends wpdb {
    public $dbhs = array();
}
$wpdb = new MUSV_Test_DB( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );
PHP
expect "exactly ONE 'Evidence queries ran through a replaced database connection' finding"
expect "downloaded JSON: complete == false; every test has evidence_connection == 'wpdb'"

echo ""
echo "Done. Delete ${CONTENT_DIR}/db.php when finished (or restore db.php.musv-bak)."
