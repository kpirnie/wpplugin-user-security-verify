# musv scanner test fixtures — PodNest edition

Same fixtures as the standalone set, but every command and file write runs
**inside the site's PodNest pod** via `podman exec`, so wp-cli, paths, and file
ownership match a real WordPress pod. **Disposable PodNest site only.**

## How this differs from the standalone set

- No `WP_PATH`. Work happens in the PHP container `pn-<site>-php` against
  `/var/www/html` (the web root bind-mounted into the pod).
- wp-cli is run from `/tmp/wp` inside the pod. That path is on tmpfs and is
  wiped when the pod restarts, so `lib.sh` reinstalls it automatically if missing.
- All fixtures land under `/var/www/html`, the only writable area in the pod —
  the rest of the pod's filesystem is read-only by design.
- `.htaccess` fixtures still fire: PodNest serves with nginx (so `.htaccess` has
  no runtime effect), but the scanner matches file **content**, not server behavior.
- PodNest WordPress pods use a direct MariaDB connection plus a Redis
  object-cache drop-in, not a `db.php`, so a normal scan uses the trusted mysqli
  path. `06_db_connection.sh` adds a `db.php` to force the fallback on purpose.

## Requirements

- Run as the **PodNest service user** (the `--user` from `pdnctl install`), so
  `podman` talks to the right rootless instance.
- The target site provisioned and its pod running (`podman ps` shows `pn-<site>-php`).
- Outbound network from the pod the first time (to fetch wp-cli into `/tmp/wp`).

## Run

```bash
export MUSV_TEST_CONFIRM=1        # required — confirms a throwaway site
export MUSV_SITE=a-dev            # the PodNest site name; pod is pn-a-dev, container pn-a-dev-php

# optional:
export PODMAN=podman              # or a full path / alias
export MUSV_SITE_URL=comp.mode.kpdev.us  # multisite subsite --url
export MUSV_EXEC_USER=            # override the exec UID if auto-detect misses

bash 01_privileges.sh
bash 02_code_paths.sh        # builds + activates the musv-fixtures plugin
bash 03_files_folders.sh
bash 03b_checksums.sh
bash 04_identity_sessions.sh
bash 05_registration.sh      # run a scan between its two cases
bash 06_db_connection.sh
bash 07_users_screen_ui.sh
```

Fixtures go into regular plugins, not `mu-plugins` (PodNest owns that directory
and the pod user cannot write to it). `02` and `07` activate the plugins that
have to execute; nothing needs a manual `plugin activate`.

Each script prints an `EXPECT:` line per fixture. After a group, open **Users >
Security Validation** in the site, run the scan, and check the findings. Flush
the object cache first (`wp cache flush`) so a stale Redis cache can't mask the
runtime privilege checks.

## Order notes

- `02_code_paths.sh` builds and activates the `musv-fixtures` plugin itself.
- `07`'s bad-AJAX fixture (`musv-fixture-badajax`) breaks **every** scan while
  active, so it is created **inactive**. Activate it only for the item-19 scan,
  then deactivate it (the script prints both commands).
- `06_db_connection.sh` writes `wp-content/db.php`; delete it when done, or no
  normal scan will use the direct connection. If the pod already had a `db.php`,
  the script tells you to back it up first.
- `05_registration.sh` leaves `default_role` changed; reset with
  `wp option update default_role subscriber`.
- The fixtures create users, drop-ins, and config files; because the pod's
  rootfs is read-only outside `/var/www/html`, nothing lands anywhere else.

## What maps to what

| Script | Fix-list items |
|---|---|
| 01_privileges.sh | 1+4, 8, 21 |
| 02_code_paths.sh | 2, 3, 7, 28 |
| 03_files_folders.sh | 5/17, 12, 13, 14, 15, 16, 29 |
| 03b_checksums.sh | 6 |
| 04_identity_sessions.sh | 9, 10, 27 |
| 05_registration.sh | 11 |
| 06_db_connection.sh | 24, 32 |
| 07_users_screen_ui.sh | 18, 19, 20, 26, 33 |

Items 22/23/30/31 are header, version, and whitespace changes with nothing to
trigger at runtime — verify those by reading the files and running
`composer cs-check`. For item 23, run a scan on both a PHP 8.2 and a PHP 8.5 pod
and confirm no `setAccessible` deprecation appears in the pod's PHP log.
