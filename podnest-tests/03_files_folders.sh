#!/usr/bin/env bash
# Items 5/17, 12, 13, 14, 15, 16, 29 — file and folder scanning. (PodNest edition)
# Everything lives under /var/www/html, the only writable area in the pod.
source "$(dirname "$0")/lib.sh"

banner "Item 5/17: unreadable directory"
mkdirp "${UPLOADS_DIR}/musv-locked"
runsh "chmod 000 '${UPLOADS_DIR}/musv-locked'" || true
expect "code paths: high 'Directory could not be read' for uploads/musv-locked; scan still finishes"

banner "Item 13: PHP open tag hidden in a non-PHP file in uploads"
printf '\x89PNG\r\n fake image <?php echo 1; ?>' | write_file "${UPLOADS_DIR}/musv-shell.png"
expect "code paths: high 'PHP code is hidden in a non-PHP file' for uploads/musv-shell.png"

banner "Item 14: .htaccess runs a non-PHP extension as PHP"
# nginx ignores .htaccess, but the scanner matches file CONTENT, so this still fires.
write_file "${UPLOADS_DIR}/.htaccess" <<'HT'
AddType application/x-httpd-php .png
HT
expect "code paths: high 'Server configuration file changes how PHP runs' for uploads/.htaccess"

banner "Item 14: .user.ini auto_prepend_file in a plugin folder"
mkdirp "${PLUGIN_DIR}/musv-fixtures"
write_file "${PLUGIN_DIR}/musv-fixtures/.user.ini" <<'INI'
auto_prepend_file=/tmp/musv-prepend.php
INI
expect "code paths: high finding for the .user.ini auto_prepend_file directive"

banner "Item 14: PHP-only AddHandler in the site root (should NOT flag)"
runsh "test -f '${ABSPATH_DIR}/.htaccess' && cp '${ABSPATH_DIR}/.htaccess' '${ABSPATH_DIR}/.htaccess.musv-bak'" || true
runsh "printf '\nAddHandler application/x-httpd-php82 .php\n' >> '${ABSPATH_DIR}/.htaccess'"
expect "the root PHP-only AddHandler produces NO finding"

banner "Item 15: symbolic link in uploads"
runsh "ln -sfn /tmp '${UPLOADS_DIR}/musv-link'"
expect "code paths: high 'Symbolic link was not scanned' for uploads/musv-link -> /tmp"

banner "Item 16/17: many small files across several batches"
mkdirp "${UPLOADS_DIR}/musv-many"
runsh "for i in \$(seq 1 5000); do echo x > '${UPLOADS_DIR}/musv-many/f'\$i'.txt'; done"
expect "code-path test runs several batches; cursor_path grows each batch; no file reported twice; later batches not slower"

banner "Item 12: theme in a registered theme directory"
REG="${CONTENT_DIR}/musv-themes-extra/musv-fixture-theme"
mkdirp "${REG}"
printf '/* Theme Name: MUSV Fixture Theme */\n' | write_file "${REG}/style.css"
write_file "${REG}/functions.php" <<'PHP'
<?php
/* MUSV TEST FIXTURE — inert. */
if ( false ) { add_filter( 'pre_user_query', 'musv_fixture_noop' ); }
PHP
# an active plugin registers the extra theme directory so musv scans it
make_plugin musv-fixture-regtheme "registers an extra theme directory" <<'PHP'
register_theme_directory( WP_CONTENT_DIR . '/musv-themes-extra' );
PHP
activate_plugin musv-fixture-regtheme
expect "code paths: the registered-dir theme's functions.php is scanned (pre_user_query matched)"

banner "Item 29: legacy multisite blogs.dir uploads (multisite only)"
if WP core is-installed --network 2>/dev/null; then
    mkdirp "${CONTENT_DIR}/blogs.dir/2/files"
    printf '<?php echo 1;' | write_file "${CONTENT_DIR}/blogs.dir/2/files/musv.php"
    expect "network scan + site 2 scan: high 'PHP file exists in the uploads folder' under blogs.dir/2/files"
else
    echo "  (skipped — not a multisite install)"
fi

echo ""
echo "Done. Item 6 (release checksums) is in 03b_checksums.sh — it needs a release-zip install."
