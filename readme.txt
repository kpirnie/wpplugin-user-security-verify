=== ModeEffect User Security Validation ===
Contributors: modeeffect, kevp75
Tags: security, users, roles, capabilities, audit
Requires at least: 6.7
Requires PHP: 8.0
Stable tag: 1.1.38
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Read-only validation of WordPress users, roles, capabilities, sessions, application passwords, identity records, visibility, and user-management code paths.

== Description ==

ModeEffect User Security Validation adds Users > Security Validation to WordPress administration. On multisite it also adds Users > Security Validation to Network Admin. It provides an administrator-controlled review of user and authorization data without changing users, roles, capabilities, sessions, options, files, or code.

The scan runs nine bounded tests sequentially through authenticated WordPress AJAX requests. A network scan adds a tenth, network-wide test. Each site scan request requires the manage_options capability, each network scan request requires manage_network_options, and every request requires a valid scan nonce for its scope. Progress is shown in the browser, individual test failures are reported, and results can be downloaded as JSON for review or evidence preservation.

The plugin is designed to expose conditions that a normal WordPress user list may conceal. User, role, capability, session, application-password, and relevant option evidence is read through WordPress's existing mysqli connection. Those read-only SELECT and SHOW queries bypass wpdb's global query filter, so a WordPress query filter cannot rewrite the authoritative evidence queries. When a db.php drop-in replaces the mysqli connection, or a multi-connection drop-in such as HyperDB or LudicrousDB is active, the scan falls back to wpdb, reports that its evidence queries are filterable, and marks the report incomplete. A normal WP_User_Query is used only for comparison with the direct database inventory.

The plugin reports indicators for human review. A finding is not automatic proof of compromise, and a scan with no findings is not a guarantee that the site is uncompromised.

== Requirements and access ==

* WordPress 6.7 or later.
* PHP 8.0 or later with the mysqli extension available to WordPress.
* A single database connection exposed by WordPress as mysqli for filter-proof evidence queries. When a db.php drop-in replaces that connection, or a multi-connection drop-in such as HyperDB or LudicrousDB is active, the scan still runs through wpdb, reports the reduced assurance as a high-severity finding, and marks the report incomplete.
* For a site scan, an authenticated administrator with the manage_options capability. On multisite, a subsite administrator's scan covers only that site's members and code.
* For a network scan on multisite, a network super administrator with the manage_network_options capability and the plugin network-activated.
* JavaScript enabled in the administrator's browser.

The plugin does not create a public endpoint. The site scan page and its AJAX requests enforce manage_options. The network scan page and its AJAX requests enforce manage_network_options. Each scope uses its own nonce, and the AJAX action verifies the nonce before accepting a test identifier. Network requests for a site are accepted only for sites on the current network.

== Installation instructions ==

1. Copy the mode-user-security-validation directory into wp-content/plugins.
2. In WordPress administration, open Plugins > Installed Plugins.
3. Activate ModeEffect User Security Validation. On multisite, network-activate it to enable the network scan.
4. Sign in with an account that has manage_options, or manage_network_options for the network scan.
5. Select Audit in the plugin's action links, or open Users > Security Validation in the site or Network Admin.

No database migration, configuration file, scheduled task, command-line command, or external service connection is required.

== Scan instructions ==

1. Preserve relevant evidence before scanning if the site is under active incident response.
2. Select Audit on the Plugins screen, or open Users > Security Validation. On multisite, use Network Admin for a scan of every site.
3. Select Run User Security Scan.
4. Keep the administration page open while the tests run. A network scan runs the per-site tests once for every site and can take considerably longer.
5. Confirm that every test shows Complete and progress reaches 100%.
6. Review findings in severity order: Critical, High, Medium, Low, then Informational.
7. Expand the practical investigation to every issue listed beneath an affected user; the visible user row shows only that user's highest severity.
8. Select Download JSON Results only when an evidence or handoff copy is required.
9. Store downloaded JSON securely because it contains account and security context.
10. After approved remediation, rerun the complete scan and compare the new results with the preserved report.

Selecting Cancel stops tests that have not yet started. It does not interrupt the current server request. Cancelling while the code-path test is between batches stops the remaining batches and marks that test Cancelled. A cancelled scan is marked incomplete and receives a medium-severity cancellation finding.

If a test fails, the report adds a high-severity incomplete-test finding and leaves complete set to false. A test response that is not valid JSON, such as a PHP fatal-error page or a timeout, is reported as a failed request with its HTTP status. Review the WordPress and PHP error logs, correct the failure, and rerun all tests. When evidence queries ran through the wpdb fallback, the report also leaves complete set to false. Do not rely on partial, cancelled, failed, or fallback results as a complete assessment.

== How the scan works ==

1. The browser requests each test individually through admin-ajax.php.
2. The server validates the administrator capability and nonce for every request.
3. In a network scan, the inventory, visibility, privileges, roles, metadata, and registration tests run once per site, and the sessions, identity, code-path, and network integrity tests run once for the network.
4. The code-path test walks each root in sorted order and runs in batches of up to 1,000 files or 32 MiB of file content, whichever comes first. Each batch resumes after the last path the previous batch scanned, without re-reading the folders before it. The browser keeps requesting batches until the test reports that no files remain.
5. Each test returns findings, aggregate metrics, and the evidence connection it used (mysqli or wpdb). Some tests also return bounded user inventory or matched code-path context.
6. The browser consolidates multiple findings for the same user on the same site into one visible row. Network scan findings name the site they apply to.
7. Site-wide findings remain separate from user findings.
8. Normal users are omitted from the visible issue-user inventory and the downloaded report's top-level users array. A user with only network-wide findings appears once, not once per site.
9. The administrator may download the completed or partial results as JSON.

== Validation tests ==

= 1. User inventory =

Builds a direct-database inventory from the WordPress users table and raw capability metadata. On multisite it covers the members of the site being scanned. Inventory context includes:

* User ID and login name.
* Database-derived roles.
* Registration timestamp and user status.
* Whether the email address is structurally valid, without displaying the address.
* Direct-capability and sensitive-capability counts.
* Active session and application-password counts.
* Authored-record counts.
* Whether a WooCommerce customer lookup record exists.

All database users are evaluated by the security tests, and the privileged_users metric counts every evaluated user. Browser inventory output is limited to the first 5,000 users to protect performance. Reaching that limit produces an informational finding.

= 2. User visibility =

Compares the complete direct-database user ID list with a normal WP_User_Query result. On multisite the comparison uses the members of the site being scanned, so users of other sites are not reported as hidden. It reports:

* Database users omitted from WordPress user-query results.
* Critical severity when an omitted user has the administrator role or administrator-level capabilities.
* Users returned by WordPress that are absent from the users table.
* Active callbacks on pre_get_users, pre_user_query, users_pre_query, users_list_table_query_args, views_users, pre_count_users, or rest_user_query.
* Database users omitted from the Users-screen query after the users_list_table_query_args filter, with critical severity when the account has administrator-level or sensitive access.
* count_users() totals or per-role counts that differ from the raw capability records.
* Users-screen role views that a views_users callback removes or whose counts it changes.

The Users-screen checks run with the Users screen simulated: the $pagenow and current-screen globals and the REQUEST_URI, SCRIPT_NAME, and PHP_SELF server values are set for the check and restored afterwards, so hiding code that runs only on that screen is triggered. No screen actions are fired.

An active user-list filter is informational when the database and query inventories agree. It becomes investigation context when a visibility discrepancy exists.

= 3. Effective privileges =

Calculates access from raw capability metadata and raw role definitions rather than filtered WordPress role or user objects. Access is resolved the way WordPress core resolves it: every capability key that names a role grants that role whatever its stored value, role capabilities merge in record order, direct entries override them (so a direct capability set to false removes a role grant), and only the first capability row by umeta_id is used, as WP_User reads it. It reports:

* Sensitive capabilities assigned directly to a user.
* Non-administrator accounts with administrator-level effective access.
* Low-trust accounts with sensitive direct grants.
* Users with 20 or more direct capabilities, with critical severity at 100 or more.
* Numeric capability keys.
* Capability keys that are neither a defined role nor granted by any role, such as a deleted or renamed role or an unrecognized custom capability.
* Sensitive capabilities WordPress grants at runtime that the raw records do not, with critical severity for administrator-level capabilities and high severity otherwise.
* Sensitive capabilities the raw records grant that WordPress denies at runtime, with high severity for administrators or administrator-level capabilities and medium severity otherwise. Denials WordPress core makes by design are excluded: DISALLOW_FILE_EDIT, DISALLOW_FILE_MODS, DISALLOW_UNFILTERED_HTML, unfiltered_upload without ALLOW_UNFILTERED_UPLOADS, and multisite restrictions for accounts that are not super administrators.

Runtime differences usually come from user_has_cap or map_meta_cap callbacks, but a poisoned persistent object cache can produce the same result. Super administrators are excluded from the runtime comparison because WordPress grants them every capability.

Non-administrator findings include the account's authored-record count and whether a WooCommerce customer record exists. Business associations are context only and do not justify privileged access. Network super administrators are reviewed by the network integrity test.

= 4. Role integrity =

Checks:

* Missing or malformed role definitions.
* Duplicate rows for the primary role-definition option.
* Malformed role capability arrays.
* Non-administrator roles that grant administrator-level capabilities.
* Additional capabilities assigned to subscriber or customer roles.
* A missing administrator role.
* An administrator role missing manage_options, create_users, or activate_plugins.
* Role definitions set by the $wp_user_roles global, usually in wp-config.php, which WordPress uses instead of the stored role option. A network scan reports this once in the network integrity test.
* Roles WordPress enforces at runtime that differ from the raw role option, including roles that exist only at runtime or are not loaded, with critical severity when a non-administrator role gains administrator-level capabilities.
* Active callbacks on the role option's option_ and pre_option_ filters.

Missing expected administrator capabilities may reflect intentional hardening and therefore require human validation. The raw role option still drives the stored-state tests; runtime differences are reported as separate findings.

= 5. Capability metadata =

Reviews raw capabilities and user_level metadata for:

* Capability values that are not valid serialized arrays.
* Capability values larger than 4,096 bytes, with critical severity above 8,000 bytes.
* Capability rows belonging to missing users.
* Duplicate capability rows for one user.
* Users without a primary capability row, on single-site installations.
* Invalid user levels outside 0 through 10.
* User levels that do not match the highest level_ capability the user's roles and capabilities grant, with high severity when the stored level is higher and low severity when it is lower.
* Duplicate user_level rows.
* Orphaned usermeta records, on single-site installations. On multisite they are reported by the network integrity test.
* Alternate capability metadata keys on non-multisite installations.

Serialized values larger than 4 MiB are not unserialized. PHP object creation is disabled while serialized data is inspected.

= 6. Sessions and application passwords =

Counts unexpired WordPress sessions and stored application-password records without returning token or credential values. A subsite scan covers that site's members. A network scan covers every user once and treats an account as privileged when it is a super administrator or holds sensitive capabilities on any site. It reports:

* Malformed session or application-password metadata.
* Metadata for missing users.
* Ten or more active sessions for any user.
* Five or more active sessions for a privileged user.
* Session tokens that expire more than 15 days from now, beyond WordPress's 14-day maximum, with high severity for privileged users and medium severity otherwise.
* Session tokens that record a login time more than one day in the future.
* Configured application passwords.
* Duplicate session-token rows.
* Duplicate application-password rows.

Session counts include only token records whose expiration is later than the current server time.

= 7. Identity and registration anomalies =

Reviews identity and registration characteristics without returning email addresses or password hashes. Password hashes are read only for users in the scan scope. A subsite scan covers that site's members. A network scan covers every user once. It reports:

* Missing or structurally invalid email addresses.
* Multiple accounts sharing the same normalized email address.
* Invalid registration timestamps.
* Registration dates more than one day in the future.
* Non-zero user_status values.
* Empty password hashes.
* Legacy 32-character unsalted MD5 hashes.
* Unrecognized password-hash formats.
* Privileged usernames with leading, trailing, repeated, or non-space whitespace, control or invisible characters, or non-ASCII characters that can imitate another login, such as a Cyrillic "admin". WordPress removes these characters when it creates accounts, so their presence points to a row written outside normal account APIs.
* Privileged usernames matching a generated-name heuristic.
* Privileged use of commonly targeted names such as admin, administrator, root, support, test, or wordpress.
* Clusters of three or more registrations within 15 minutes. Zero registration dates are excluded from clusters.

Registration clusters may be legitimate imports or checkout activity. Username-pattern findings are heuristics and require ownership validation.

= 8. Registration defaults =

Reports whether registration is enabled and checks the default registration role. A network scan checks every site. It reports:

* A critical finding when the default role grants administrator-level capabilities.
* A high-severity finding when the default role grants other sensitive capabilities.
* A medium-severity finding when the default role is not defined in the raw role option. New accounts receive that role key and gain its access if a role with that name is later defined.

On multisite, WordPress ignores each site's registration setting and uses the network registration setting instead, so the test reads that setting. Its value (none, user, blog, or all) is reported as registration_mode. Users can register accounts when it is user or all. In blog mode, logged-in users can create new sites.

= 9. User-related code paths =

Performs bounded static pattern matching against:

* Active plugins.
* Network-active plugins on multisite.
* Must-use plugins.
* Inactive plugins and themes, in the default themes folder and every registered theme directory.
* The active parent and child themes, resolved from their stored theme roots the way WordPress resolves them.
* The uploads folder, and legacy multisite blogs.dir uploads.
* PHP files in the wp-content root, including drop-ins.
* wp-config.php, in the WordPress folder or one level above it, matching how WordPress finds it.
* Files set by the PHP auto_prepend_file and auto_append_file settings.
* .htaccess and PHP user INI (.user.ini by default) files in the WordPress root, the wp-content root, and every scanned folder.

A subsite scan on multisite covers only that site's active plugins and themes, its own uploads folder, and its own legacy blogs.dir folder. Network-active plugins, must-use plugins, inactive plugins and themes, wp-content root files, wp-config.php, prepend or append files, and root server configuration files are covered by the network scan, which combines every site's plugins and themes and scans each folder once. The network scan's uploads folders include every site's uploads.

Any PHP file in the uploads folder receives a high-severity finding regardless of its contents. A non-PHP file in the uploads folder, such as an image or text file, that contains a PHP open tag receives a high-severity finding. A PHP file in the wp-content root that is not a known drop-in receives a medium-severity finding. A non-empty auto_prepend_file or auto_append_file setting receives a high-severity finding. Findings for inactive code are titled Inactive rather than Active.

Server configuration files receive findings for:

* auto_prepend_file or auto_append_file directives, at high severity.
* AddHandler or AddType directives that run non-PHP extensions, such as png or ico, as PHP, at high severity.
* AddHandler or AddType PHP handler assignments outside the WordPress root, at medium severity.
* SetHandler or ForceType PHP handlers outside the WordPress root, at high severity.

PHP-only handler assignments in the WordPress root are not reported because hosts set them there.

Active plugin entries that contain an absolute path or a parent-directory segment are not scanned and receive a high-severity finding. Plugin folders that resolve outside the plugins directory, such as through a symbolic link, are not scanned and receive a medium-severity finding. Other symbolic links in scanned folders are not followed and receive a finding naming their target, at high severity in the uploads folder and medium severity elsewhere. Directories that cannot be read are skipped without failing the test and receive a finding, at high severity in the uploads folder and medium severity elsewhere.

The scanner reviews PHP (including inc, phar, php3 through php8, pht, and phtml files), JavaScript, and CSS for code capable of:

* Filtering or replacing WordPress user queries, including REST API user queries.
* Changing Users-screen query arguments, views, or counts, including replacing count_users() results.
* Hiding roles from administration.
* Altering runtime capabilities or capability mapping.
* Altering or replacing the network super administrator list.
* Creating or updating users.
* Signing users in without the login form, swapping the current user, or hooking authenticate, check_password, or wp_authenticate_user.
* Adding capabilities or changing roles.
* Writing capability metadata directly.
* Referencing any site's capability metadata key directly.
* Writing directly to the users or usermeta tables.
* Rewriting wpdb queries globally.
* Hiding or removing rows on the Users screen, including rows selected by login text through :contains(), .column-username, or a row lookup such as .closest('tr') or .parents('tr').
* Rewriting the role-view counts on the Users screen.
* Targeting a specific privileged user ID or login for concealment.

Function and hook names are matched as whole words, so add_cap does not match add_capability and set_role does not match reset_role. Every matching category in a file is reported as its own finding, so a file that both hides users and signs in a hard-coded identity receives both findings. Static matching identifies review candidates and does not prove malicious intent. Request-controlled user creation, direct table writes, query rewriting, and targeted concealment receive increased severity. Sign-in and credential-check code is high severity when the file reads request input and critical when it also hard-codes a user ID, a login, or a request-value comparison. Single sign-on, two-factor, and login plugins use these hooks legitimately.

The scan covers this plugin's folder. Its own files are skipped only when they match the checksums the release build writes into checksums.sha256; a changed or unlisted plugin file receives a high-severity finding and is scanned. Without the checksums file, as in a development checkout, the plugin's own files are scanned too. The scan covers every directory under each root, including vendor, node_modules, tests, cache, and languages. It skips JavaScript and CSS files larger than 1 MiB and reads at most the first 1 MiB of other files in the uploads folder. PHP files larger than 4 MiB are not read and receive a medium-severity finding, because large PHP files can contain packed or obfuscated code. Files are scanned in batches of up to 1,000 files or 32 MiB per request with no overall file limit, and each batch returns at most 100 matched paths in structured code_paths output.

= 10. Network integrity =

Runs only in a network scan. It reports:

* Every network super administrator for ownership review, and super administrator logins absent from the users table.
* A high-severity finding when the $super_admins global is set, usually in wp-config.php, because WordPress then ignores the site_admins network option.
* Active site_option_site_admins or pre_site_option_site_admins callbacks, at high severity when the super administrators WordPress enforces differ from the stored list and informational otherwise.
* A high-severity finding when the $wp_user_roles global is set, because WordPress then ignores every site's stored role option.
* Users omitted from the network Users-screen query after the users_list_table_query_args filter, and network Users-screen views that a views_users-network callback removes or whose counts it changes.
* Users absent from a network-wide WP_User_Query result, with critical severity when the account is privileged on any site.
* Users returned by WordPress that are absent from the users table.
* Users that belong to no site on the network.
* Orphaned usermeta records.

Super administrators are matched by exact login, as WordPress core matches them.

== Sensitive capability coverage ==

Administrator-level capabilities:

* activate_plugins, create_users, delete_plugins, delete_users, edit_files, edit_plugins, edit_themes, edit_users.
* install_plugins, install_themes, manage_options, promote_users, remove_users, switch_themes.
* update_core, update_plugins, update_themes.
* manage_network, manage_network_options, manage_network_plugins, manage_network_themes, manage_network_users, manage_sites, and upgrade_network.

Additional sensitive capabilities:

* delete_themes, edit_theme_options, export, import, list_users, manage_woocommerce, unfiltered_html, and unfiltered_upload.
* ure_create_capabilities, ure_create_roles, ure_delete_capabilities, ure_delete_roles, ure_edit_roles, ure_manage_options, and ure_reset_roles.

Custom capabilities outside these lists may still be powerful and require application-specific review.

== Severity levels ==

* Critical: immediate hidden privilege, persistence, account-integrity, or severe authorization risk.
* High: strong privilege, visibility, metadata, credential, or integrity anomaly.
* Medium: suspicious or consequential condition requiring validation.
* Low: weak indicator, configuration concern, or account-hygiene issue.
* Informational: investigation context or an expected administrative code path that is not proof of a problem.

The visible row for a user uses the highest severity among all of that user's findings while retaining every underlying issue and recommendation.

== Result-review instructions ==

For every finding:

1. Record the MUSV finding ID and severity.
2. Preserve relevant database rows, files, and logs before changing the affected item.
3. Validate the user, role, integration, or code path with its documented owner.
4. Review the finding summary and recommendation.
5. Investigate related findings for the same user and any referenced file path.
6. Apply remediation only through an approved change process.
7. Rerun the entire scan and confirm that the intended finding is resolved without introducing another anomaly.

Critical findings should be handled as potential incident-response items. High findings require prompt technical review. Medium, low, and informational findings should not be ignored because they may explain the origin of a higher-severity condition.

== Report contents ==

Each server-side finding contains:

* A deterministic MUSV-prefixed finding ID.
* Severity.
* Title and summary.
* A recommended investigation or remediation step.
* User ID and login name when applicable.
* Site ID for findings from a network scan's per-site tests, or 0 otherwise.

The downloaded JSON contains:

* generated_at: browser-generated UTC timestamp.
* plugin_version: active plugin version.
* scope: site or network.
* complete: whether every test finished without cancellation or request failure and every evidence query used the direct mysqli connection.
* tests: raw per-test and per-batch findings, metrics, evidence connection, and test-specific bounded context.
* findings: complete ungrouped finding list.
* code_paths: matched code paths from every code-path batch.
* user_summaries: findings grouped by affected user.
* users: issue-user inventory used by the visible report.

The visible report and top-level users array include only users with findings. The raw inventory test stored inside tests retains bounded inventory context and can include users without findings. Treat every downloaded JSON file as sensitive administrative evidence.

== Data handling and privacy ==

The interface and JSON report do not return:

* Email-address values.
* Password-hash values.
* Session-token values.
* Application-password values.
* Database credentials.
* Customer names, addresses, order details, or payment details.
* Post or page content.

The report does contain account IDs, login names, role and capability context, registration timestamps, counts, file paths, metrics, and security findings. Restrict access and follow the organization's evidence-retention requirements.

The plugin does not send scan data to ModeEffect or another remote service. JSON generation and download occur in the administrator's browser.

== Read-only guarantees ==

The direct query helper accepts only statements beginning with SELECT or SHOW. The scan does not:

* Insert, update, or delete database records.
* Add, edit, demote, promote, disable, or remove users.
* Change roles or capabilities.
* Destroy sessions or revoke application passwords.
* Edit active code or configuration.
* Automatically remediate findings.

The visibility and role tests apply WordPress's own user-list, views, and capability filters to compare their results, so active callbacks on those filters run during the scan. The Users-screen globals and server values the visibility tests simulate are restored when each check finishes.

Recommendations are instructions for an authorized administrator and are not executed by the plugin.

== Scope and limitations ==

This is a focused user-security validation tool. It is not a complete malware scanner, vulnerability scanner, forensic acquisition system, access-log analyzer, or payment-security assessment.

Important limitations:

* Static matching can produce false positives and cannot prove malicious intent.
* Obfuscated, generated, encrypted, remote, database-stored, or unfamiliar code may not match known patterns.
* The code test does not cover WordPress core, server configuration other than the prepend and append settings and per-directory .htaccess and user INI files, or files outside its selected roots. Inactive code is scanned but does not run through WordPress hooks; it can still be requested directly.
* Users-screen hiding that depends on conditions the scan cannot simulate, such as the request not being an AJAX request, the network admin constant, or the rendered page, may not fire during the visibility checks. Rendered-page CSS and JavaScript hiding is covered by the code scan.
* Runtime capability and role comparisons reflect the filters and object cache active during the AJAX request that runs each test.
* Files excluded by extension or size limits are not inspected. Symbolic links are reported but not followed. Unreadable directories are reported but not scanned. Oversized PHP files are reported, not read.
* The release checksums ship inside the plugin folder, so they detect general file injection but not tampering that also rewrites checksums.sha256.
* A subsite scan does not cover network-active plugins, must-use plugins, drop-ins, or network super administrators. Use the network scan for those.
* When a db.php drop-in replaces the mysqli connection, or a multi-connection drop-in such as HyperDB or LudicrousDB is active, evidence queries run through wpdb and can be altered by query filters or the drop-in itself. The scan reports this condition and marks the report incomplete, and its results should be confirmed against an offline database export.
* Database checks do not establish the integrity of every database table.
* Counts and timestamps represent the state observed as each AJAX test runs.
* A user or code path may be legitimate even when it matches a high-risk pattern.
* A clean scan does not validate ownership, guarantee credential secrecy, or rule out prior compromise.

Use the results with integrity checks, malware scanning, dependency review, access-log analysis, credential rotation, multi-factor authentication, and human ownership validation during an incident investigation.

== Operating guidance ==

* Run a complete scan after suspected unauthorized access, user cleanup, role changes, credential rotation, or code remediation.
* Preserve evidence before changing suspicious users, metadata, sessions, role definitions, or code.
* Validate every privileged account with the site owner.
* Investigate highest-severity findings first, then review informational code paths that may explain user or capability creation.
* Rerun after remediation and compare results.
* Do not treat disappearance from the current report as a substitute for historical evidence.

== Troubleshooting instructions ==

= The page is not available under Users =

Confirm that the plugin is active and the current administrator has manage_options. For the Network Admin page, confirm the plugin is network-activated and the current user has manage_network_options.

= A test could not complete =

Review the WordPress debug log and PHP error log without exposing credentials or customer data. Each failed test is logged with a [mode-user-security-validation] prefix, the test ID, the site ID, and the exception details. A response that is not valid JSON is reported with its HTTP status. Correct the failure and rerun the entire scan.

= The code-path test reports many files =

Legitimate user-management and authorization code is intentionally surfaced for human review. Start with critical and high findings, request-controlled operations, direct table writes, query rewriting, and code targeting specific user rows.

= The code-path test takes a long time =

The test scans every file under each root in batches of up to 1,000 files or 32 MiB. Keep the page open until it completes. Cancelling stops further batches, marks the code-path test Cancelled, and marks the scan incomplete.

= A user exists in the database but not in WordPress queries =

Treat the discrepancy as significant. Preserve evidence, inspect user-query filters and code-path findings, validate ownership, and review object-cache consistency before containment.

== Changelog ==

= 1.1.38 =
* Fixed indentation of the network Users-screen check in the network integrity test.
* Changed the plugin header license to GPLv2 or later to match readme.txt, composer.json, and LICENSE.
* Added legacy multisite blogs.dir uploads to the code-path scan.
* Fixed the add_cap and set_role code-path patterns matching longer names such as add_capability and reset_role; every pattern now matches whole words only.
* Changed the identity test to read password hashes only for users in the scan scope.
* Fixed the inventory privileged_users metric counting only the displayed rows instead of every evaluated user.
* Fixed the WooCommerce customer table check treating underscores in the table name as wildcards.
* Changed evidence queries to use the wpdb fallback when HyperDB, LudicrousDB, or another multi-connection drop-in is active, because its connection handle can belong to a replica or another dataset.
* Stopped calling the deprecated ReflectionProperty::setAccessible() on PHP 8.1 and later.
* Fixed users with network-wide findings appearing once per site in Users With Issues and the downloaded users array.
* Added a finding for user_level values that do not match the level the user's roles and capabilities grant.
* Added REQUEST_URI, SCRIPT_NAME, and PHP_SELF to the simulated Users screen so path-conditional hiding code fires.
* Fixed a non-JSON test response, such as a fatal-error page or timeout, surfacing as a raw SyntaxError; it is now reported as a failed request with its HTTP status.
* Fixed a cancel during code-path batches marking that test Complete; it is now marked Cancelled.
* Changed code-path batches to resume after the last scanned path in sorted order instead of re-walking each root from the start.
* Added a finding for directories that cannot be read.
* Changed code-path batches to stop at 32 MiB of file content as well as 1,000 files, so one batch cannot read gigabytes and time out.
* Added findings for symbolic links in scanned folders instead of skipping them silently.
* Added detection of .htaccess and PHP user INI directives that prepend code, run non-PHP extensions as PHP, or assign PHP handlers outside the WordPress root.
* Added a high-severity finding for PHP open tags hidden in non-PHP files, such as images and text files, in the uploads folder.
* Added themes in registered theme directories to the code-path scan, and resolved active theme roots from the stored stylesheet_root and template_root options.
* Added findings for a default registration role with sensitive capabilities and for a default registration role that does not exist.
* Changed the db.php fallback to mark the report incomplete and to report its high-severity finding independently of the code-path test.
* Added findings for session tokens that expire beyond WordPress's maximum or record a login time in the future.
* Added a finding for privileged logins with hidden whitespace, control or invisible characters, or non-ASCII lookalike characters.
* Added unfiltered_upload to the sensitive capabilities, excluding core's ALLOW_UNFILTERED_UPLOADS denial from runtime mismatches.
* Added detection of pre_count_users, rest_user_query, site_option_site_admins, and pre_site_option_site_admins callbacks, and a network finding when the runtime super administrator list differs from the stored list.
* Changed the code-path scan to cover this plugin's folder, skipping its own files only when they match the release checksums.
* Added a high-severity finding for plugin files that differ from the release checksums.
* Added checksums.sha256 to the release build.
* Fixed one unreadable directory failing the whole code-path test.
* Added detection of Users-screen rows hidden by login text and of scripts that rewrite the role-view counts.
* Added targeted-user findings for logins named in :contains() selectors.
* Fixed the code-path test reporting only the first matching category per file; every matching category is now reported, so the highest severity is no longer masked.
* Fixed role keys stored with a false value being treated as no role; WordPress grants a role for any key that names it.
* Fixed direct capabilities set to false not overriding role grants, and duplicate capability rows being merged instead of using the first row by umeta_id, as WordPress core does.

= 1.1.7 =
* Added runtime capability checks that report sensitive capabilities granted at runtime but not in the database, and database capabilities denied at runtime outside core's own restrictions.
* Added findings for role definitions set by the $wp_user_roles global, roles that differ between the stored option and runtime, and active role-option filters.
* Added code-path detection for auto-login, current-user switching, credential-check bypass, and hard-coded sign-in identities or passwords.
* Added Users-screen visibility checks for the list-table query, count_users() totals, and role views, with the Users screen simulated so screen-conditional hiding runs.
* Expanded the code-path scan to inactive plugins and themes, the uploads folder, PHP files in the wp-content root, wp-config.php, and PHP prepend and append files.
* Added findings for any PHP file in the uploads folder, unknown PHP files in the wp-content root, and non-empty auto_prepend_file or auto_append_file settings.
* Fixed alignment whitespace in the registration defaults test.

= 1.1.0 =
* Added a network scan for super administrators on multisite, with per-site tests run for every site and a network integrity test.
* Fixed subsite administrators being able to view user data for the whole network; subsite scans now cover only that site's members and code.
* Fixed users outside the current subsite being reported as hidden.
* Fixed super administrators defined by the $super_admins global being missed, and super administrator logins being matched without case sensitivity.
* Fixed the alternate capability-key check never matching because of wpdb placeholder escaping.
* Added a wpdb fallback when a db.php drop-in replaces the mysqli connection, with a finding that evidence queries are filterable.
* Added error logging for failed tests.
* Changed the code-path scan to run in batches of 1,000 files with no overall file limit.
* Expanded code-path coverage to every directory and to inc, phar, php3 through php8, pht, and phtml files, and matched any site's capability metadata key.
* Added a finding for PHP files larger than 4 MiB instead of skipping them silently.
* Added findings for active plugin entries that traverse or resolve outside the plugins directory.
* Added a finding for capability keys that are neither a defined role nor granted by any role.
* Folded the content and commerce context test into the effective privileges test.
* Moved the default registration role check into a separate registration defaults test.
* Read multisite registration from the network option and report registration_mode
* Fixed zero registration dates forming a false registration cluster.
* Removed password hashes from the shared users query and cached it per request.
* Added PHP_CodeSniffer with the WordPress Coding Standards.

= 1.0.0 =
* Added direct-database user, role, capability, session, identity, visibility, and business-context validation.
* Added bounded active-code review for user creation, authorization changes, direct database writes, query filters, and Users-screen concealment.
* Added AJAX progress, cancellation, severity summaries, issue-only visible user reporting, downloadable JSON results, and full operating instructions.
