#!/usr/bin/env bash
# Items 24, 32 — wpdb fallback marks the report incomplete.
# Writes a wp-content/db.php drop-in that extends wpdb and exposes a $dbhs
# property (as HyperDB/LudicrousDB do). It is a thin passthrough, not a real
# multi-db driver, so the scanner falls back to wpdb.
source "$(dirname "$0")/lib.sh"

banner "Items 24/32: db.php drop-in forces the wpdb fallback"
cat > "${CONTENT_DIR}/db.php" <<'PHP'
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
echo "Done. Delete ${CONTENT_DIR}/db.php when finished with this test."
