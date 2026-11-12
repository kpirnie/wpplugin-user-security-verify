# shellcheck shell=bash
# Shared helpers for the musv scanner test fixtures — PodNest edition.
# Everything runs inside the site's PHP container (pn-<site>-php) via podman exec,
# so wp-cli, file ownership and paths match a real PodNest WordPress pod.
# Source this from each NN_*.sh script; do not run it directly.
#
# Run these as the PodNest service user (the --user from `pdnctl install`), so
# `podman` talks to the right rootless instance.

set -euo pipefail

# refuse to run unless the operator confirmed this is a disposable site
if [ "${MUSV_TEST_CONFIRM:-}" != "1" ]; then
    echo "Refusing to run: set MUSV_TEST_CONFIRM=1 to confirm this is a throwaway site." >&2
    echo "  MUSV_TEST_CONFIRM=1 MUSV_SITE=<site> bash $0" >&2
    exit 1
fi

# the PodNest site name; the pod is pn-<site> and the PHP container pn-<site>-php
PN_SITE="${MUSV_SITE:?set MUSV_SITE to the PodNest site name (the pod is pn-<site>)}"
PODMAN="${PODMAN:-podman}"
PHP_CT="pn-${PN_SITE}-php"

# confirm the container is up
if ! ${PODMAN} container exists "${PHP_CT}" 2>/dev/null; then
    echo "Container ${PHP_CT} not found. Is the site provisioned and running?" >&2
    echo "Available pn-* containers:" >&2
    ${PODMAN} ps --format '  {{.Names}}' | grep -E '^\s+pn-' || true
    exit 1
fi

# run exec as the site UID so fixtures are owned like real site files; auto-detect
# from the container config, override with MUSV_EXEC_USER
SITE_UID="${MUSV_EXEC_USER:-$(${PODMAN} inspect --format '{{.Config.User}}' "${PHP_CT}" 2>/dev/null | cut -d: -f1)}"
EXEC_USER_ARG=()
if [ -n "${SITE_UID}" ]; then
    EXEC_USER_ARG=(--user "${SITE_UID}")
fi

# wp-cli lives at /tmp/wp inside the pod on tmpfs, so it is wiped on pod restart.
# install it the same way PodNest does if it is not there.
WP_BIN="/tmp/wp"
ensure_wpcli() {
    if ${PODMAN} exec "${EXEC_USER_ARG[@]}" "${PHP_CT}" test -x "${WP_BIN}" 2>/dev/null; then
        return
    fi
    echo "Installing wp-cli into ${PHP_CT}:${WP_BIN} ..." >&2
    ${PODMAN} exec "${EXEC_USER_ARG[@]}" "${PHP_CT}" sh -c \
        "wget -q https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -O ${WP_BIN} && chmod +x ${WP_BIN}"
}
ensure_wpcli

# wp-cli wrapper — argv passthrough, no shell inside the container.
# The pod sets open_basedir, so wp-cli emits a harmless is_readable(/var/www)
# warning on every bootstrap; drop just that line, keep all other stderr.
WP() {
    ${PODMAN} exec "${EXEC_USER_ARG[@]}" "${PHP_CT}" "${WP_BIN}" --path=/var/www/html --no-color --allow-root "$@" \
        2> >(grep -v 'open_basedir restriction in effect' >&2)
}

# run a PHP snippet inside WordPress via the in-pod mysqli connection.
# $1 = PHP body (no <?php); remaining args arrive as $args[0], $args[1], ...
# Used instead of `wp db query`, which the pod blocks (putenv/proc_open disabled).
wp_eval_php() {
    local body="$1"; shift
    printf '<?php\n%s\n' "${body}" | ${PODMAN} exec -i "${EXEC_USER_ARG[@]}" "${PHP_CT}" sh -c 'cat > /tmp/musv-op.php'
    WP eval-file /tmp/musv-op.php "$@"
}

# a disposable --url for multisite subsite commands; override with MUSV_SITE_URL
URL_ARG=()
if [ -n "${MUSV_SITE_URL:-}" ]; then
    URL_ARG=(--url="${MUSV_SITE_URL}")
fi

# write stdin to a file inside the container, owned by the exec user
write_file() { # $1 = container path
    ${PODMAN} exec -i "${EXEC_USER_ARG[@]}" "${PHP_CT}" sh -c "cat > '$1'"
}
mkdirp() { ${PODMAN} exec "${EXEC_USER_ARG[@]}" "${PHP_CT}" mkdir -p "$1"; }
runsh()  { ${PODMAN} exec "${EXEC_USER_ARG[@]}" "${PHP_CT}" sh -c "$1"; }

# resolve the db table prefix and common container paths once
PREFIX="$(WP config get table_prefix)"
CONTENT_DIR="$(WP eval 'echo WP_CONTENT_DIR;')"
UPLOADS_DIR="$(WP eval '$u = wp_upload_dir( null, false ); echo untrailingslashit( $u["basedir"] );')"
PLUGIN_DIR="$(WP eval 'echo WP_PLUGIN_DIR;')"
MU_DIR="$(WP eval 'echo WPMU_PLUGIN_DIR;')"
ABSPATH_DIR="$(WP eval 'echo untrailingslashit( ABSPATH );')"

mkdirp "${MU_DIR}"

banner() { echo ""; echo "=== $* ==="; }
expect() { echo "  EXPECT: $*"; }

# create a user if the login is free; echo its ID either way
ensure_user() {
    local login="$1" role="$2" id
    id="$(WP user get "${login}" --field=ID 2>/dev/null || true)"
    if [ -z "${id}" ]; then
        id="$(WP user create "${login}" "${login}@musv-test.local" --role="${role}" --porcelain)"
    fi
    echo "${id}"
}

# replace a user's primary capability record with a raw serialized value, bypassing the role API
set_raw_caps() {
    wp_eval_php 'global $wpdb; $u=(int)$args[0]; $k=$wpdb->prefix."capabilities"; $wpdb->delete($wpdb->usermeta, array("user_id"=>$u,"meta_key"=>$k)); $wpdb->insert($wpdb->usermeta, array("user_id"=>$u,"meta_key"=>$k,"meta_value"=>(string)$args[1])); clean_user_cache($u); wp_cache_delete($u, "user_meta");' "$1" "$2"
}

# add a SECOND capability row for a user without removing the first (duplicate-row case)
add_caps_row() {
    wp_eval_php 'global $wpdb; $u=(int)$args[0]; $wpdb->insert($wpdb->usermeta, array("user_id"=>$u,"meta_key"=>$wpdb->prefix."capabilities","meta_value"=>(string)$args[1])); clean_user_cache($u); wp_cache_delete($u, "user_meta");' "$1" "$2"
}

# set a raw user_login directly, bypassing sanitize_user()
set_user_login() {
    wp_eval_php 'global $wpdb; $u=(int)$args[0]; $wpdb->update($wpdb->users, array("user_login"=>(string)$args[1]), array("ID"=>$u)); clean_user_cache($u);' "$1" "$2"
}

# PodNest owns wp-content/mu-plugins (it mounts its SSO plugin there), so the pod
# user can't write into it. Fixtures therefore go into regular plugins, which are
# writable, and the ones that must execute are activated.

# make_plugin SLUG DESCRIPTION  — plugin header + PHP body (from stdin) as the main file
make_plugin() {
    mkdirp "${PLUGIN_DIR}/$1"
    { printf '<?php\n/**\n * Plugin Name: MUSV %s\n * Description: %s — test fixture.\n */\ndefined( "ABSPATH" ) || exit;\n' "$1" "$2"; cat; } \
        | write_file "${PLUGIN_DIR}/$1/$1.php"
}

activate_plugin()   { WP plugin activate "$1"   >/dev/null; }
deactivate_plugin() { WP plugin deactivate "$1" >/dev/null 2>&1 || true; }
