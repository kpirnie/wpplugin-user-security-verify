# shellcheck shell=bash
# Shared helpers for the musv scanner test fixtures.
# Source this from each NN_*.sh script; do not run it directly.

set -euo pipefail

# refuse to run unless the operator confirmed this is a disposable site
if [ "${MUSV_TEST_CONFIRM:-}" != "1" ]; then
    echo "Refusing to run: set MUSV_TEST_CONFIRM=1 to confirm this is a throwaway site." >&2
    echo "  MUSV_TEST_CONFIRM=1 bash $0" >&2
    exit 1
fi

# wp-cli wrapper. point WP_PATH at the WordPress root if not running from inside it.
WP_PATH="${WP_PATH:-$PWD}"
WP="wp --path=${WP_PATH} --skip-plugins=mode-user-security-validation"

# a wp call that DOES load musv, for the few places we need its own context (none by default)
WP_RAW="wp --path=${WP_PATH}"

# resolve the db table prefix and common paths once
PREFIX="$(${WP} config get table_prefix)"
CONTENT_DIR="$(${WP} eval 'echo WP_CONTENT_DIR;')"
UPLOADS_DIR="$(${WP} eval '$u = wp_upload_dir( null, false ); echo untrailingslashit( $u["basedir"] );')"
PLUGIN_DIR="$(${WP} eval 'echo WP_PLUGIN_DIR;')"
MU_DIR="$(${WP} eval 'echo WPMU_PLUGIN_DIR;')"
ABSPATH_DIR="$(${WP} eval 'echo untrailingslashit( ABSPATH );')"

mkdir -p "${MU_DIR}"

# a disposable --url for multisite subsite commands; override with MUSV_SITE_URL
SITE_URL="${MUSV_SITE_URL:-}"
URL_ARG=""
if [ -n "${SITE_URL}" ]; then
    URL_ARG="--url=${SITE_URL}"
fi

banner() {
    echo ""
    echo "=== $* ==="
}

expect() {
    echo "  EXPECT: $*"
}

# create a user if the login is free; echo its ID either way
ensure_user() {
    local login="$1" role="$2" id
    id="$(${WP} user get "${login}" --field=ID 2>/dev/null || true)"
    if [ -z "${id}" ]; then
        id="$(${WP} user create "${login}" "${login}@musv-test.local" --role="${role}" --porcelain)"
    fi
    echo "${id}"
}

# write a serialized wp_capabilities value directly, bypassing the role API
set_raw_caps() {
    local user_id="$1" serialized="$2"
    ${WP} db query "DELETE FROM ${PREFIX}usermeta WHERE user_id=${user_id} AND meta_key='${PREFIX}capabilities'"
    ${WP} db query "INSERT INTO ${PREFIX}usermeta (user_id, meta_key, meta_value) VALUES (${user_id}, '${PREFIX}capabilities', '${serialized}')"
}
