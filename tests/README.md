# musv scanner test fixtures

Sets up the conditions the ModeEffect User Security Validation plugin should
detect, so you can run a scan and confirm each fix fires. **Disposable site
only** — these scripts create hidden-admin users, inert code fixtures, and a
db.php drop-in. Every PHP fixture is either guarded off (`if ( false )`) or a
harmless admin-side filter; they exist to trip the scanner's static matching,
not to do anything.

## Requirements

- wp-cli on PATH, run from the WordPress root (or set `WP_PATH`).
- The musv plugin installed and active on the site.
- For the unreadable-directory test, PHP must run as a non-root user.

## Run

```bash
export MUSV_TEST_CONFIRM=1          # required — confirms a throwaway site
export WP_PATH=/var/www/html        # optional if you run from the WP root
export MUSV_SITE_URL=sub.example.com # optional, for multisite subsite commands

bash 01_privileges.sh
bash 02_code_paths.sh
wp plugin activate musv-fixture-hide
bash 03_files_folders.sh
bash 03b_checksums.sh
bash 04_identity_sessions.sh
bash 05_registration.sh      # run a scan between its two cases
bash 06_db_connection.sh
bash 07_users_screen_ui.sh
```

Each script prints an `EXPECT:` line per fixture describing the finding the
scan should produce. After running a group, open **Users > Security
Validation**, run the scan, and check the findings against those lines.

## Order notes

- `02_code_paths.sh` drops a `musv-fixture-hide` plugin; activate it before
  scanning (`wp plugin activate musv-fixture-hide`).
- `07_users_screen_ui.sh` drops `musv-fixture-bad-ajax.php`, which breaks
  **every** scan while present. Delete it before running other UI tests:
  `rm <WPMU_PLUGIN_DIR>/musv-fixture-bad-ajax.php`.
- `06_db_connection.sh` writes `wp-content/db.php`. Delete it when done or no
  normal scan will use the direct connection.
- `05_registration.sh` leaves `default_role` changed; reset with
  `wp option update default_role subscriber`.

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
`composer cs-check`.
