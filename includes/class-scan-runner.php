<?php
/**
 * Read-only user security validation tests.
 *
 * @package Mode\UserSecurityValidation
 * @author Kevin Brent
 */

namespace Mode\UserSecurityValidation;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReflectionProperty;
use RuntimeException;
use SplFileInfo;
use WP_Screen;
use WP_User;
use WP_User_Query;
use mysqli;
use wpdb;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Runs the read-only user security validation tests against raw database records and active code.
 */
final class Scan_Runner {
	private const MAX_INVENTORY_USERS = 5000;
	private const CODE_BATCH_FILES    = 1000;
	private const CODE_BATCH_BYTES    = 33554432;
	private const MAX_CODE_FILE_BYTES = 1048576;
	private const MAX_PHP_FILE_BYTES  = 4194304;
	private const MAX_SESSION_SECONDS = 1296000;

	/**
	 * File extensions scanned as PHP.
	 *
	 * @var string[]
	 */
	private const PHP_EXTENSIONS = array( 'inc', 'phar', 'php', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8', 'pht', 'phtml' );

	/**
	 * PHP files WordPress expects in the wp-content root: drop-ins and the directory index.
	 *
	 * @var string[]
	 */
	private const KNOWN_CONTENT_FILES = array(
		'advanced-cache.php',
		'blog-deleted.php',
		'blog-inactive.php',
		'blog-suspended.php',
		'db-error.php',
		'db.php',
		'fatal-error-handler.php',
		'index.php',
		'install.php',
		'maintenance.php',
		'object-cache.php',
		'php-error.php',
		'sunrise.php',
	);

	/**
	 * This plugin's own code files, relative to its folder. The code scan skips them because they contain every pattern it matches.
	 *
	 * @var string[]
	 */
	private const OWN_FILES = array(
		'assets/admin.css',
		'assets/admin.js',
		'includes/class-plugin.php',
		'includes/class-scan-runner.php',
		'mode-user-security-validation.php',
		'views/admin-page.php',
	);

	/**
	 * Administrator-level capabilities.
	 *
	 * @var string[]
	 */
	private const CRITICAL_CAPABILITIES = array(
		'activate_plugins',
		'create_users',
		'delete_plugins',
		'delete_users',
		'edit_files',
		'edit_plugins',
		'edit_themes',
		'edit_users',
		'install_plugins',
		'install_themes',
		'manage_network',
		'manage_network_options',
		'manage_network_plugins',
		'manage_network_themes',
		'manage_network_users',
		'manage_options',
		'manage_sites',
		'promote_users',
		'remove_users',
		'switch_themes',
		'update_core',
		'update_plugins',
		'update_themes',
		'upgrade_network',
	);

	/**
	 * Additional sensitive capabilities.
	 *
	 * @var string[]
	 */
	private const SENSITIVE_CAPABILITIES = array(
		'delete_themes',
		'edit_theme_options',
		'export',
		'import',
		'list_users',
		'manage_woocommerce',
		'unfiltered_html',
		// user role editor capabilities.
		'ure_create_capabilities',
		'ure_create_roles',
		'ure_delete_capabilities',
		'ure_delete_roles',
		'ure_edit_roles',
		'ure_manage_options',
		'ure_reset_roles',
	);

	/**
	 * Tests a network scan runs once instead of once per site.
	 *
	 * @var string[]
	 */
	private const NETWORK_TESTS = array( 'sessions', 'identity', 'code_paths', 'network_integrity' );

	/**
	 * WordPress database abstraction.
	 *
	 * @var wpdb
	 */
	private wpdb $wpdb;

	/**
	 * Direct mysqli connection, or null when a drop-in replaced it.
	 *
	 * @var mysqli|null
	 */
	private ?mysqli $database = null;

	/**
	 * Raw role definitions for the current site.
	 *
	 * @var array<string,array<string,mixed>>
	 */
	private array $role_definitions;

	/**
	 * Cached raw capability rows grouped by user ID.
	 *
	 * @var array<int,array<int,array<string,mixed>>>|null
	 */
	private ?array $capability_rows_by_user = null;

	/**
	 * Scan scope: 'site' or 'network'.
	 *
	 * @var string
	 */
	private string $scope;

	/**
	 * Current site's member IDs, or null when the test covers every user.
	 *
	 * @var array<int,bool>|null
	 */
	private ?array $member_ids = null;

	/**
	 * Site ID tagged on findings during a network scan's per-site tests.
	 *
	 * @var int
	 */
	private int $site_id = 0;

	/**
	 * Site label prefixed to findings during a network scan's per-site tests.
	 *
	 * @var string
	 */
	private string $site_label = '';

	/**
	 * Code-path batch cursor.
	 *
	 * @var array{root?:int,path?:string}
	 */
	private array $cursor = array();

	/**
	 * Cached network sites.
	 *
	 * @var array<int,array{blog_id:int,label:string}>|null
	 */
	private ?array $network_sites = null;

	/**
	 * Cached network-wide membership and sensitive access.
	 *
	 * @var array{members:array<int,bool>,sensitive:array<int,bool>}|null
	 */
	private ?array $network_access = null;

	/**
	 * Cached super administrator user IDs.
	 *
	 * @var array<int,bool>|null
	 */
	private ?array $super_admin_ids = null;

	/**
	 * Cached capabilities granted by any role on the current site.
	 *
	 * @var array<string,bool>|null
	 */
	private ?array $role_capabilities = null;

	/**
	 * Cached users-table rows, without password hashes.
	 *
	 * @var array<int, array<string,mixed>>|null
	 */
	private ?array $database_users = null;

	/**
	 * Findings raised while resolving code-scan roots.
	 *
	 * @var array<int,array<string,mixed>>
	 */
	private array $root_findings = array();

	/**
	 * Code-scan root kinds keyed by root path: active, inactive, uploads, content, config, or prepend.
	 *
	 * @var array<string,string>
	 */
	private array $root_kinds = array();

	/**
	 * Normalized path prefixes the code scan skips.
	 *
	 * @var string[]
	 */
	private array $excluded_paths = array();

	/**
	 * Normalized paths of this plugin's own files that match the release checksums.
	 *
	 * @var array<string,bool>
	 */
	private array $verified_own_files = array();

	/**
	 * Captures the WordPress database handle, the scan scope, and the raw role definitions.
	 *
	 * @param string $scope Scan scope: 'site' for a single site or subsite, 'network' for a network scan.
	 * @throws RuntimeException When WordPress database access is unavailable.
	 */
	public function __construct( string $scope = 'site' ) {
		global $wpdb;

		if ( ! $wpdb instanceof wpdb ) {
			throw new RuntimeException( 'WordPress database access is unavailable.' );
		}

		$this->wpdb        = $wpdb;
		$this->scope       = is_multisite() && 'network' === $scope ? 'network' : 'site';
		$database_property = new ReflectionProperty( wpdb::class, 'dbh' );

		// ReflectionProperty::setAccessible() is a no-op from PHP 8.1 and deprecated in 8.5.
		if ( PHP_VERSION_ID < 80100 ) {
			$database_property->setAccessible( true );
		}

		$database = $database_property->getValue( $wpdb );

		// HyperDB and LudicrousDB keep several connections, so dbh can be a replica or another dataset's connection.
		$this->database         = $database instanceof mysqli && ! property_exists( $wpdb, 'dbhs' ) ? $database : null;
		$role_definitions       = $this->safe_unserialize( $this->database_option_value( $this->wpdb->prefix . 'user_roles' ) );
		$this->role_definitions = is_array( $role_definitions ) ? $role_definitions : array();
	}

	/**
	 * Lists the validation tests the browser runs, in order.
	 *
	 * @param string $scope Scan scope the manifest is built for: 'site' or 'network'.
	 * @return array<int, array{id:string,label:string,description:string,scope:string}>
	 */
	public static function manifest( string $scope = 'site' ): array {
		$tests = array(
			array(
				'id'          => 'inventory',
				'label'       => __( 'User inventory', 'mode-user-security-validation' ),
				'description' => __( 'Builds a direct-database inventory without exposing password hashes, session tokens, or application-password values.', 'mode-user-security-validation' ),
			),
			array(
				'id'          => 'visibility',
				'label'       => __( 'User visibility', 'mode-user-security-validation' ),
				'description' => __( 'Compares direct database users with WordPress user queries and checks Users-screen filters that can hide accounts.', 'mode-user-security-validation' ),
			),
			array(
				'id'          => 'privileges',
				'label'       => __( 'Effective privileges', 'mode-user-security-validation' ),
				'description' => __( 'Calculates roles and effective access from raw database records to find hidden administrator-level privileges.', 'mode-user-security-validation' ),
			),
			array(
				'id'          => 'roles',
				'label'       => __( 'Role integrity', 'mode-user-security-validation' ),
				'description' => __( 'Checks every role for unexpected plugin, theme, user-management, options, and core-update privileges.', 'mode-user-security-validation' ),
			),
			array(
				'id'          => 'metadata',
				'label'       => __( 'Capability metadata', 'mode-user-security-validation' ),
				'description' => __( 'Detects malformed, duplicated, oversized, numeric, alternate-prefix, and orphaned capability records.', 'mode-user-security-validation' ),
			),
			array(
				'id'          => 'sessions',
				'label'       => __( 'Sessions and application passwords', 'mode-user-security-validation' ),
				'description' => __( 'Counts active sessions and application passwords without returning token or credential values.', 'mode-user-security-validation' ),
			),
			array(
				'id'          => 'identity',
				'label'       => __( 'Identity and registration anomalies', 'mode-user-security-validation' ),
				'description' => __( 'Reviews email validity, duplicate identities, registration dates, status values, and account clusters.', 'mode-user-security-validation' ),
			),
			array(
				'id'          => 'registration',
				'label'       => __( 'Registration defaults', 'mode-user-security-validation' ),
				'description' => __( 'Checks whether registration is enabled and whether the default registration role grants administrator-level access.', 'mode-user-security-validation' ),
			),
			array(
				'id'          => 'code_paths',
				'label'       => __( 'User-related code paths', 'mode-user-security-validation' ),
				'description' => __( 'Identifies PHP, JavaScript, and CSS in plugins, themes, uploads, and configuration files that creates users, signs users in, changes access, filters user queries, or hides rows on the Users screen.', 'mode-user-security-validation' ),
			),
		);

		if ( 'network' === $scope && is_multisite() ) {
			$tests[] = array(
				'id'          => 'network_integrity',
				'label'       => __( 'Network integrity', 'mode-user-security-validation' ),
				'description' => __( 'Reviews super administrators, network-wide user visibility, users without a site, and orphaned user metadata.', 'mode-user-security-validation' ),
			);
		}

		return array_map(
			static fn ( array $test ): array => $test + array( 'scope' => self::test_scope( $test['id'] ) ),
			$tests
		);
	}

	/**
	 * Returns whether a test runs once per scan or once per site.
	 *
	 * Network scans run "network" tests once and "site" tests once per site.
	 *
	 * @param string $test_id Test identifier.
	 * @return string 'network' or 'site'.
	 */
	public static function test_scope( string $test_id ): string {
		return in_array( $test_id, self::NETWORK_TESTS, true ) ? 'network' : 'site';
	}

	/**
	 * Runs one validation test in the current site context.
	 *
	 * @param string $test_id Test identifier from the manifest.
	 * @param array  $cursor  Code-path batch cursor with a root offset and the last scanned path in that root.
	 * @return array{test_id:string,site_id:int,findings:array<int,array<string,mixed>>,metrics:array<string,int|string>,users?:array<int,array<string,mixed>>,code_paths?:array<int,array<string,mixed>>,next?:array{root:int,path:string}|null} Test result.
	 * @throws RuntimeException When the test identifier is unknown or not available in this scope.
	 */
	public function run( string $test_id, array $cursor = array() ): array {
		$callbacks = array(
			'inventory'         => 'test_inventory',
			'visibility'        => 'test_visibility',
			'privileges'        => 'test_privileges',
			'roles'             => 'test_roles',
			'metadata'          => 'test_metadata',
			'sessions'          => 'test_sessions',
			'identity'          => 'test_identity',
			'registration'      => 'test_registration',
			'code_paths'        => 'test_code_paths',
			'network_integrity' => 'test_network_integrity',
		);

		if ( ! isset( $callbacks[ $test_id ] ) || ( 'network_integrity' === $test_id && 'network' !== $this->scope ) ) {
			throw new RuntimeException( 'Unknown validation test.' );
		}

		$this->member_ids = null;
		$this->site_id    = 0;
		$this->site_label = '';
		$this->cursor     = $cursor;

		if ( is_multisite() && ( 'site' === $this->scope || 'site' === self::test_scope( $test_id ) ) ) {
			$this->member_ids = array_fill_keys( array_keys( $this->database_capability_rows_by_user() ), true );
		}

		if ( 'network' === $this->scope && 'site' === self::test_scope( $test_id ) ) {
			$this->site_id    = get_current_blog_id();
			$this->site_label = $this->label_for_site( $this->site_id );
		}

		$method                        = $callbacks[ $test_id ];
		$result                        = $this->{$method}();
		$result['test_id']             = $test_id;
		$result['site_id']             = $this->site_id;
		$result['evidence_connection'] = null === $this->database ? 'wpdb' : 'mysqli';

		return $result;
	}


	/**
	 * Builds the bounded user inventory from raw database records.
	 *
	 * @return array{findings:array<int,array<string,mixed>>,metrics:array<string,int|string>,users:array<int,array<string,mixed>>}
	 */
	private function test_inventory(): array {
		$rows                        = $this->scoped_users();
		$post_counts                 = $this->authored_content_counts();
		$customer_ids                = $this->woocommerce_customer_ids();
		$session_counts              = $this->database_session_counts();
		$application_password_counts = $this->database_application_password_counts();
		$users                       = array();
		$findings                    = array();
		$privileged_count            = 0;

		foreach ( $rows as $position => $row ) {
			$user_id = (int) $row['ID'];
			$access  = $this->database_user_access( $user_id );

			if ( $access['sensitive'] ) {
				++$privileged_count;
			}

			if ( $position >= self::MAX_INVENTORY_USERS ) {
				continue;
			}

			$users[] = array(
				'id'                    => $user_id,
				'login'                 => (string) $row['user_login'],
				'roles'                 => $access['roles'],
				'registered'            => (string) $row['user_registered'],
				'email_valid'           => false !== filter_var( (string) $row['user_email'], FILTER_VALIDATE_EMAIL ),
				'status'                => (int) $row['user_status'],
				'direct_cap_count'      => count( $access['direct'] ),
				'sensitive_cap_count'   => count( $access['sensitive'] ),
				'sessions'              => $session_counts[ $user_id ] ?? 0,
				'application_passwords' => $application_password_counts[ $user_id ] ?? 0,
				'authored_records'      => $post_counts[ $user_id ] ?? 0,
				'customer_record'       => isset( $customer_ids[ $user_id ] ),
				'site_id'               => $this->site_id,
				'site'                  => $this->site_label,
			);
		}

		if ( count( $rows ) > self::MAX_INVENTORY_USERS ) {
			$findings[] = $this->finding(
				'informational',
				'Browser inventory display was bounded',
				'All ' . count( $rows ) . ' database users were evaluated by the security tests, but only the first ' . self::MAX_INVENTORY_USERS . ' are displayed in the browser.',
				'Use the findings and aggregate metrics as the authoritative scan result.'
			);
		}

		return array(
			'findings' => $findings,
			'metrics'  => array(
				'database_users'        => count( $rows ),
				'inventory_rows'        => count( $users ),
				'privileged_users'      => $privileged_count,
				'active_sessions'       => array_sum( $session_counts ),
				'application_passwords' => array_sum( $application_password_counts ),
			),
			'users'    => $users,
		);
	}

	/**
	 * Compares database users with WordPress user-query results and reports hidden accounts.
	 *
	 * @return array{findings:array<int,array<string,mixed>>,metrics:array<string,int|string>}
	 */
	private function test_visibility(): array {
		$database_rows  = $this->scoped_users();
		$database_ids   = array_map( 'intval', array_column( $database_rows, 'ID' ) );
		$query          = new WP_User_Query(
			array(
				'fields'      => 'ID',
				'number'      => -1,
				'count_total' => false,
			)
		);
		$query_ids      = array_map( 'intval', $query->get_results() );
		$missing_ids    = array_values( array_diff( $database_ids, $query_ids ) );
		$unexpected_ids = array_values( array_diff( $query_ids, $database_ids ) );
		$findings       = array();

		foreach ( $missing_ids as $user_id ) {
			$row                        = $this->find_database_user( $database_rows, $user_id );
			$access                     = $this->database_user_access( $user_id );
			$administrator_capabilities = array_values( array_intersect( self::CRITICAL_CAPABILITIES, $access['effective'] ) );
			$has_administrator_role     = in_array( 'administrator', $access['roles'], true );

			if ( $has_administrator_role || $administrator_capabilities ) {
				$findings[] = $this->finding(
					'critical',
					'Hidden user has administrator-level access',
					'The account exists in the users table, is absent from WP_User_Query, and has ' . ( $has_administrator_role ? 'the administrator role' : 'administrator-level capabilities: ' . $this->bounded_list( $administrator_capabilities ) ) . '.',
					'Treat this as a potential persistence account. Preserve evidence, validate ownership, and inspect every user-list filter before containment.',
					$user_id,
					$row['user_login'] ?? ''
				);
				continue;
			}

			$findings[] = $this->finding(
				$access['sensitive'] ? 'critical' : 'high',
				'Database user is hidden from WordPress user queries',
				'The account exists in the users table but is absent from a normal WP_User_Query result.',
				'Inspect active pre_user_query and users_pre_query filters and validate the account owner.',
				$user_id,
				$row['user_login'] ?? ''
			);
		}

		if ( $unexpected_ids ) {
			$findings[] = $this->finding(
				'high',
				'WordPress returned users absent from the users table',
				'WordPress user queries returned unexpected IDs: ' . implode( ', ', array_map( 'strval', array_slice( $unexpected_ids, 0, 20 ) ) ) . '.',
				'Review object caching, user-query filters, and database consistency.'
			);
		}

		$role_slugs         = array_map( 'strval', array_keys( wp_roles()->get_names() ) );
		$screen             = $this->in_users_screen(
			'users',
			function () use ( $role_slugs ): array {
				$counts = count_users();
				$views  = array( 'all' => (int) $counts['total_users'] );

				foreach ( array_merge( $role_slugs, array( 'none' ) ) as $role_slug ) {
					if ( ! empty( $counts['avail_roles'][ $role_slug ] ) ) {
						$views[ $role_slug ] = (int) $counts['avail_roles'][ $role_slug ];
					}
				}

				return array(
					'ids'    => $this->users_screen_query_ids(
						array(
							'number' => 20,
							'offset' => 0,
							'role'   => '',
							'search' => '',
							'fields' => 'all_with_meta',
						)
					),
					'counts' => $counts,
					'views'  => $this->filtered_view_changes( 'views_users', $views ),
				);
			}
		);
		$screen_missing_ids = array_values( array_diff( $database_ids, $screen['ids'], $missing_ids ) );
		$count_differences  = $this->user_count_differences( $screen['counts'], $role_slugs );

		foreach ( $screen_missing_ids as $user_id ) {
			$row                        = $this->find_database_user( $database_rows, $user_id );
			$access                     = $this->database_user_access( $user_id );
			$administrator_capabilities = array_values( array_intersect( self::CRITICAL_CAPABILITIES, $access['effective'] ) );
			$has_administrator_role     = in_array( 'administrator', $access['roles'], true );

			$findings[] = $this->finding(
				$has_administrator_role || $administrator_capabilities || $access['sensitive'] ? 'critical' : 'high',
				$has_administrator_role || $administrator_capabilities ? 'Users screen hides a user with administrator-level access' : 'Users screen hides a database user',
				'The account exists in the users table and in normal WordPress user queries, but is absent from the Users-screen query.',
				'Inspect active users_list_table_query_args, pre_get_users, and pre_user_query callbacks, including ones that only run on the Users screen, and validate the account owner.',
				$user_id,
				(string) ( $row['user_login'] ?? '' )
			);
		}

		if ( $count_differences ) {
			$findings[] = $this->finding(
				'high',
				'Users-screen counts differ from the database',
				'count_users() does not match the raw capability records: ' . $this->bounded_list( $count_differences ) . '.',
				'Inspect active pre_count_users and query filters, and compare the Users screen with the direct database inventory.'
			);
		}

		if ( $screen['views'] ) {
			$findings[] = $this->finding(
				'high',
				'Users-screen views are altered by a filter',
				'The views_users filter changed the role views: ' . $this->bounded_list( $screen['views'] ) . '.',
				'Inspect active views_users callbacks and compare the Users screen with the direct database inventory.'
			);
		}

		$pre_get_users_callbacks    = has_filter( 'pre_get_users' );
		$pre_user_query_callbacks   = has_filter( 'pre_user_query' );
		$users_pre_query_callbacks  = has_filter( 'users_pre_query' );
		$list_table_query_callbacks = has_filter( 'users_list_table_query_args' );
		$views_users_callbacks      = has_filter( 'views_users' );
		$pre_count_users_callbacks  = has_filter( 'pre_count_users' );
		$rest_user_query_callbacks  = has_filter( 'rest_user_query' );

		if ( $pre_get_users_callbacks || $pre_user_query_callbacks || $users_pre_query_callbacks || $list_table_query_callbacks || $views_users_callbacks || $pre_count_users_callbacks || $rest_user_query_callbacks ) {
			$findings[] = $this->finding(
				'informational',
				'User-list filters are active',
				'One or more active callbacks can alter WordPress user-query results or the Users-screen list. No issue is implied when database and query inventories match.',
				'Review the user-related code-path results if any account visibility discrepancy is reported.'
			);
		}

		return array(
			'findings' => $findings,
			'metrics'  => array(
				'database_users'      => count( $database_ids ),
				'query_users'         => count( $query_ids ),
				'hidden_users'        => count( $missing_ids ),
				'unexpected_users'    => count( $unexpected_ids ),
				'screen_hidden_users' => count( $screen_missing_ids ),
				'count_differences'   => count( $count_differences ),
				'altered_views'       => count( $screen['views'] ),
				'query_filters_seen'  => ( $pre_get_users_callbacks || $pre_user_query_callbacks || $users_pre_query_callbacks || $list_table_query_callbacks || $views_users_callbacks || $pre_count_users_callbacks || $rest_user_query_callbacks ) ? 'yes' : 'no',
			),
		);
	}

	/**
	 * Reports direct, hidden, numeric, and undefined privilege grants calculated from raw records.
	 *
	 * @return array{findings:array<int,array<string,mixed>>,metrics:array<string,int|string>}
	 */
	private function test_privileges(): array {
		$findings               = array();
		$privileged_count       = 0;
		$direct_sensitive_count = 0;
		$runtime_mismatch_count = 0;
		$post_counts            = $this->authored_content_counts();
		$customer_ids           = $this->woocommerce_customer_ids();

		foreach ( $this->scoped_users() as $row ) {
			$user_id             = (int) $row['ID'];
			$access              = $this->database_user_access( $user_id );
			$direct              = $access['direct'];
			$direct_sensitive    = array_values( array_intersect( $direct, $this->all_sensitive_capabilities() ) );
			$effective_sensitive = $access['sensitive'];
			$roles               = $access['roles'];
			$is_administrator    = in_array( 'administrator', $roles, true );
			$has_low_trust_role  = (bool) array_intersect( $roles, array( 'subscriber', 'customer', 'contributor', 'author' ) );

			if ( $effective_sensitive ) {
				++$privileged_count;
			}

			if ( $direct_sensitive ) {
				++$direct_sensitive_count;
				$findings[] = $this->finding(
					$has_low_trust_role ? 'critical' : 'high',
					'Sensitive capabilities are assigned directly to a user',
					'Direct grants bypass normal role review. Capabilities: ' . $this->bounded_list( $direct_sensitive ) . '.',
					'Confirm the account owner and business requirement, then remove unnecessary direct grants through an approved change.',
					$user_id,
					(string) $row['user_login']
				);
			}

			if ( ! $is_administrator && array_intersect( self::CRITICAL_CAPABILITIES, $effective_sensitive ) ) {
				$findings[] = $this->finding(
					$has_low_trust_role ? 'critical' : 'high',
					'Non-administrator account has administrator-level access',
					'Effective capabilities include: ' . $this->bounded_list( array_values( array_intersect( self::CRITICAL_CAPABILITIES, $effective_sensitive ) ) ) . '. Authored records: ' . ( $post_counts[ $user_id ] ?? 0 ) . '; WooCommerce customer record: ' . ( isset( $customer_ids[ $user_id ] ) ? 'yes' : 'no' ) . '.',
					'Treat the account as privileged regardless of its displayed role and validate it with the site owner.',
					$user_id,
					(string) $row['user_login']
				);
			}

			if ( count( $direct ) >= 100 ) {
				$findings[] = $this->finding(
					'critical',
					'User has an unusually large direct capability set',
					'The account has ' . count( $direct ) . ' direct capabilities. Normal WordPress users usually inherit capabilities from roles.',
					'Preserve the capability record, validate the account, and investigate how the direct grants were created.',
					$user_id,
					(string) $row['user_login']
				);
			} elseif ( count( $direct ) >= 20 ) {
				$findings[] = $this->finding(
					'high',
					'User has many direct capabilities',
					'The account has ' . count( $direct ) . ' direct capabilities outside its assigned roles.',
					'Review the account and replace direct grants with the narrowest approved role where practical.',
					$user_id,
					(string) $row['user_login']
				);
			}

			if ( $access['undefined'] ) {
				$findings[] = $this->finding(
					'medium',
					'User has an undefined role or unrecognized capability',
					'The capability record grants keys that are not a defined role and are not granted by any role: ' . $this->bounded_list( $access['undefined'] ) . '.',
					'Confirm whether each key is a deleted or renamed role, or a custom capability granted intentionally.',
					$user_id,
					(string) $row['user_login']
				);
			}

			if ( $access['numeric'] ) {
				$findings[] = $this->finding(
					'high',
					'User capability record contains numeric keys',
					'Numeric entries are not normal role or capability names and can indicate bulk privilege manipulation.',
					'Preserve and review the serialized capability metadata before making changes.',
					$user_id,
					(string) $row['user_login']
				);
			}

			$runtime = $this->runtime_access_differences( $user_id, $access['effective'] );

			if ( $runtime['granted'] || $runtime['denied'] ) {
				++$runtime_mismatch_count;
			}

			if ( $runtime['granted'] ) {
				$findings[] = $this->finding(
					array_intersect( self::CRITICAL_CAPABILITIES, $runtime['granted'] ) ? 'critical' : 'high',
					'Capabilities are granted at runtime but not in the database',
					'WordPress grants capabilities the raw role and capability records do not: ' . $this->bounded_list( $runtime['granted'] ) . '.' . ( is_multisite() && is_super_admin( $user_id ) ? ' WordPress treats the account as a super administrator at runtime, but it is not in the stored super administrator list.' : '' ),
					'Inspect active user_has_cap, map_meta_cap, and super administrator filters for conditions tied to this account. A poisoned persistent object cache can cause the same mismatch, so compare again after flushing it.',
					$user_id,
					(string) $row['user_login']
				);
			}

			if ( $runtime['denied'] ) {
				$findings[] = $this->finding(
					$is_administrator || array_intersect( self::CRITICAL_CAPABILITIES, $runtime['denied'] ) ? 'high' : 'medium',
					'Capabilities in the database are denied at runtime',
					'The raw records grant capabilities WordPress denies outside its own file-modification and multisite restrictions: ' . $this->bounded_list( $runtime['denied'] ) . '. Runtime denial can conceal the real access level of the account from reviewers.',
					'Inspect active map_meta_cap and user_has_cap filters for do_not_allow mappings tied to this account. A poisoned persistent object cache can cause the same mismatch, so compare again after flushing it.',
					$user_id,
					(string) $row['user_login']
				);
			}
		}

		return array(
			'findings' => $this->deduplicate_findings( $findings ),
			'metrics'  => array(
				'privileged_users'                 => $privileged_count,
				'users_with_direct_sensitive_caps' => $direct_sensitive_count,
				'runtime_access_mismatches'        => $runtime_mismatch_count,
			),
		);
	}

	/**
	 * Checks the raw role definitions for missing, malformed, or over-privileged roles.
	 *
	 * @return array{findings:array<int,array<string,mixed>>,metrics:array<string,int|string>}
	 */
	private function test_roles(): array {
		$findings         = array();
		$sensitive        = $this->all_sensitive_capabilities();
		$role_count       = 0;
		$role_option_rows = (int) $this->direct_value(
			$this->wpdb->prepare(
				'SELECT COUNT(option_id) FROM %i WHERE option_name = %s',
				$this->wpdb->options,
				$this->wpdb->prefix . 'user_roles'
			)
		);

		if ( $role_option_rows > 1 ) {
			$findings[] = $this->finding(
				'high',
				'Database contains duplicate role-definition options',
				'The raw role option exists in ' . $role_option_rows . ' rows, which creates ambiguity about the active definition.',
				'Preserve all rows and determine how the duplicate option was created before cleanup.'
			);
		}

		if ( ! $this->role_definitions ) {
			$findings[] = $this->finding(
				'critical',
				'Database role definitions are missing or malformed',
				'The raw ' . $this->wpdb->prefix . 'user_roles option did not contain a valid role array.',
				'Preserve the option value and restore roles only from a verified known-good definition.'
			);
		}

		foreach ( $this->role_definitions as $role_slug => $role_data ) {
			++$role_count;

			if ( ! is_array( $role_data ) || ! isset( $role_data['capabilities'] ) || ! is_array( $role_data['capabilities'] ) ) {
				$findings[] = $this->finding(
					'high',
					'Role definition is malformed',
					'Role "' . $role_slug . '" does not contain a valid capability array.',
					'Preserve and compare the role option with a known-good definition.'
				);
				continue;
			}

			$granted           = array_keys( array_filter( (array) ( $role_data['capabilities'] ?? array() ) ) );
			$granted_sensitive = array_values( array_intersect( $granted, $sensitive ) );

			if ( 'administrator' !== $role_slug && array_intersect( self::CRITICAL_CAPABILITIES, $granted_sensitive ) ) {
				$severity   = in_array( $role_slug, array( 'subscriber', 'customer', 'contributor', 'author' ), true ) ? 'critical' : 'high';
				$findings[] = $this->finding(
					$severity,
					'Non-administrator role grants administrator-level access',
					'Role "' . $role_slug . '" grants: ' . $this->bounded_list( array_values( array_intersect( self::CRITICAL_CAPABILITIES, $granted_sensitive ) ) ) . '.',
					'Preserve the role definition, confirm intent, and remove unauthorized capabilities through an approved change.'
				);
			}

			if ( in_array( $role_slug, array( 'subscriber', 'customer' ), true ) ) {
				$unexpected = array_values( array_diff( $granted, array( 'read', 'level_0' ) ) );

				if ( $unexpected ) {
					$findings[] = $this->finding(
						array_intersect( $unexpected, $sensitive ) ? 'high' : 'medium',
						'Low-trust role has additional capabilities',
						'Role "' . $role_slug . '" grants: ' . $this->bounded_list( $unexpected ) . '.',
						'Confirm each capability is required for customers or subscribers.'
					);
				}
			}
		}

		$administrator = $this->role_definitions['administrator'] ?? null;

		if ( ! is_array( $administrator ) ) {
			$findings[] = $this->finding(
				'critical',
				'Administrator role is missing',
				'WordPress does not currently expose the standard administrator role.',
				'Investigate role-option tampering and restore only from a known-good role definition.'
			);
		} else {
			$missing = array_values(
				array_filter(
					array( 'manage_options', 'create_users', 'activate_plugins' ),
					static fn ( string $capability ): bool => empty( $administrator['capabilities'][ $capability ] )
				)
			);

			if ( $missing ) {
				$findings[] = $this->finding(
					'medium',
					'Administrator role is missing expected capabilities',
					'Missing capabilities: ' . implode( ', ', $missing ) . '.',
					'Confirm whether this is intentional hardening or unauthorized role modification.'
				);
			}
		}

		$role_option_name      = $this->wpdb->prefix . 'user_roles';
		$roles_global_finding  = 'network' === $this->scope ? null : $this->user_roles_global_finding();
		$runtime_role_findings = $this->runtime_role_findings();

		if ( null !== $roles_global_finding ) {
			$findings[] = $roles_global_finding;
		}

		$findings = array_merge( $findings, $runtime_role_findings );

		if ( has_filter( 'option_' . $role_option_name ) || has_filter( 'pre_option_' . $role_option_name ) ) {
			$findings[] = $this->finding(
				'informational',
				'Role-option filters are active',
				'One or more active callbacks filter the ' . $role_option_name . ' option, so the role definitions WordPress enforces can differ from the stored value. No issue is implied when no runtime role difference is reported.',
				'Review the callbacks if any runtime role difference is reported.'
			);
		}

		return array(
			'findings' => $findings,
			'metrics'  => array(
				'roles_reviewed'           => $role_count,
				'role_issues'              => count( $findings ),
				'role_option_rows'         => $role_option_rows,
				'runtime_role_differences' => count( $runtime_role_findings ),
			),
		);
	}

	/**
	 * Detects malformed, duplicated, oversized, orphaned, and alternate-prefix capability metadata.
	 *
	 * @return array{findings:array<int,array<string,mixed>>,metrics:array<string,int|string>}
	 */
	private function test_metadata(): array {
		$capability_key    = $this->wpdb->prefix . 'capabilities';
		$findings          = array();
		$rows              = $this->direct_rows(
			$this->wpdb->prepare(
				'SELECT umeta_id, user_id, meta_key, meta_value FROM %i WHERE meta_key = %s ORDER BY user_id, umeta_id',
				$this->wpdb->usermeta,
				$capability_key
			)
		);
		$rows_by_user      = array();
		$database_user_ids = array_fill_keys( array_map( 'intval', array_column( $this->database_users(), 'ID' ) ), true );

		foreach ( $rows as $row ) {
			$user_id                    = (int) $row['user_id'];
			$rows_by_user[ $user_id ][] = $row;
			$value                      = $this->safe_unserialize( (string) $row['meta_value'] );

			if ( ! is_array( $value ) ) {
				$findings[] = $this->finding(
					'high',
					'Capability metadata is malformed',
					'The capability value is not a valid serialized array.',
					'Preserve the row and compare it with a known-good WordPress capability record.',
					$user_id
				);
				continue;
			}

			if ( strlen( (string) $row['meta_value'] ) > 4096 ) {
				$findings[] = $this->finding(
					strlen( (string) $row['meta_value'] ) > 8000 ? 'critical' : 'high',
					'Capability metadata is unusually large',
					'The serialized capability record is ' . strlen( (string) $row['meta_value'] ) . ' bytes.',
					'Review direct grants and investigate whether capabilities were copied in bulk.',
					$user_id
				);
			}

			if ( ! isset( $database_user_ids[ $user_id ] ) ) {
				$findings[] = $this->finding(
					'high',
					'Capability metadata references a missing user',
					'A capability row exists without a matching users-table record.',
					'Preserve the row and remove it only after confirming the user was intentionally deleted.',
					$user_id
				);
			}
		}

		foreach ( $rows_by_user as $user_id => $user_rows ) {
			if ( count( $user_rows ) > 1 ) {
				$findings[] = $this->finding(
					'high',
					'User has duplicate capability rows',
					'The account has ' . count( $user_rows ) . ' rows for the primary capability key.',
					'Preserve the rows and determine which value WordPress is using before cleanup.',
					$user_id
				);
			}
		}

		foreach ( is_multisite() ? array() : $database_user_ids as $user_id => $unused ) {
			if ( ! isset( $rows_by_user[ $user_id ] ) ) {
				$findings[] = $this->finding(
					'low',
					'User has no primary capability record',
					'The account has no row for the raw ' . $capability_key . ' metadata key and therefore has no database-assigned site role.',
					'Confirm that the account is intentionally unassigned.',
					(int) $user_id
				);
			}
		}

		$level_key      = $this->wpdb->prefix . 'user_level';
		$level_rows     = $this->direct_rows(
			$this->wpdb->prepare(
				'SELECT umeta_id, user_id, meta_value FROM %i WHERE meta_key = %s ORDER BY user_id, umeta_id',
				$this->wpdb->usermeta,
				$level_key
			)
		);
		$levels_by_user = array();

		foreach ( $level_rows as $level_row ) {
			$user_id                      = (int) $level_row['user_id'];
			$levels_by_user[ $user_id ][] = $level_row;
			$level_value                  = (string) $level_row['meta_value'];

			if ( ! ctype_digit( $level_value ) || (int) $level_value > 10 ) {
				$findings[] = $this->finding(
					'high',
					'User level metadata is invalid',
					'The raw user_level value is not an integer from 0 through 10.',
					'Preserve the row and investigate direct metadata manipulation.',
					$user_id
				);
			}
		}

		foreach ( $levels_by_user as $user_id => $user_level_rows ) {
			if ( count( $user_level_rows ) > 1 ) {
				$findings[] = $this->finding(
					'medium',
					'User has duplicate level metadata',
					'The account has ' . count( $user_level_rows ) . ' rows for the primary user_level key.',
					'Preserve the rows and determine which value was created outside normal account management.',
					$user_id
				);
			}

			$stored_level = (string) $user_level_rows[0]['meta_value'];

			if ( ! ctype_digit( $stored_level ) || ! isset( $database_user_ids[ $user_id ] ) ) {
				continue;
			}

			$expected_level = 0;

			foreach ( $this->database_user_access( $user_id )['effective'] as $capability ) {
				if ( preg_match( '/^level_(\d+)$/', $capability, $level_match ) ) {
					$expected_level = max( $expected_level, (int) $level_match[1] );
				}
			}

			if ( (int) $stored_level !== $expected_level ) {
				$findings[] = $this->finding(
					(int) $stored_level > $expected_level ? 'high' : 'low',
					'User level does not match the assigned role',
					'The raw user_level value is ' . (int) $stored_level . ', but the account\'s roles and capabilities grant level ' . $expected_level . '. Legacy code that reads user_level trusts the stored value.',
					'Preserve the row, confirm the account role, and investigate how the level was changed outside normal role assignment.',
					$user_id
				);
			}
		}

		$orphan_rows = is_multisite() ? 0 : $this->orphan_meta_rows();

		if ( $orphan_rows > 0 ) {
			$findings[] = $this->finding(
				'medium',
				'Orphaned user metadata exists',
				$orphan_rows . ' usermeta rows do not have a matching users-table record.',
				'Review the metadata keys and remove records only after evidence and ownership review.'
			);
		}

		$alternate_keys = $this->direct_rows(
			$this->wpdb->prepare(
				'SELECT meta_key, COUNT(umeta_id) AS row_count FROM %i WHERE meta_key LIKE %s AND meta_key <> %s GROUP BY meta_key ORDER BY meta_key',
				$this->wpdb->usermeta,
				'%capabilities',
				$capability_key
			)
		);

		if ( ! is_multisite() && $alternate_keys ) {
			foreach ( $alternate_keys as $alternate_key ) {
				$findings[] = $this->finding(
					'medium',
					'Alternate capability metadata key exists',
					'Key "' . $alternate_key['meta_key'] . '" appears on ' . (int) $alternate_key['row_count'] . ' row(s).',
					'Confirm that the key is not residual multisite or migration data before removal.'
				);
			}
		}

		return array(
			'findings' => $findings,
			'metrics'  => array(
				'capability_rows'  => count( $rows ),
				'orphan_meta_rows' => $orphan_rows,
				'alternate_keys'   => count( $alternate_keys ),
				'user_level_rows'  => count( $level_rows ),
			),
		);
	}

	/**
	 * Counts sessions and application passwords without returning token or credential values.
	 *
	 * @return array{findings:array<int,array<string,mixed>>,metrics:array<string,int|string>}
	 */
	private function test_sessions(): array {
		$findings                 = array();
		$session_rows             = $this->direct_rows(
			$this->wpdb->prepare(
				'SELECT user_id, meta_value FROM %i WHERE meta_key = %s',
				$this->wpdb->usermeta,
				'session_tokens'
			)
		);
		$application_rows         = $this->direct_rows(
			$this->wpdb->prepare(
				'SELECT user_id, meta_value FROM %i WHERE meta_key = %s',
				$this->wpdb->usermeta,
				'_application_passwords'
			)
		);
		$active_sessions          = 0;
		$application_passwords    = 0;
		$database_users           = $this->database_users_by_id();
		$session_rows_by_user     = array();
		$application_rows_by_user = array();
		$now                      = time();

		foreach ( $session_rows as $row ) {
			$user_id = (int) $row['user_id'];

			if ( ! $this->in_scope( $user_id ) ) {
				continue;
			}

			$tokens                             = $this->safe_unserialize( (string) $row['meta_value'] );
			$session_rows_by_user[ $user_id ][] = $row;

			if ( ! is_array( $tokens ) ) {
				$findings[] = $this->finding(
					'high',
					'Session metadata is malformed',
					'The session_tokens value is not a valid serialized array. Token data was not returned by the scan.',
					'Preserve the row and investigate direct metadata manipulation.',
					$user_id,
					isset( $database_users[ $user_id ] ) ? (string) $database_users[ $user_id ]['user_login'] : ''
				);
			}

			$count            = $this->active_token_count( is_array( $tokens ) ? $tokens : array() );
			$active_sessions += $count;

			$long_lived   = 0;
			$future_login = 0;

			foreach ( is_array( $tokens ) ? $tokens : array() as $token ) {
				if ( ! is_array( $token ) ) {
					continue;
				}

				if ( (int) ( $token['expiration'] ?? 0 ) > $now + self::MAX_SESSION_SECONDS ) {
					++$long_lived;
				}

				if ( (int) ( $token['login'] ?? 0 ) > $now + DAY_IN_SECONDS ) {
					++$future_login;
				}
			}

			if ( $long_lived ) {
				$findings[] = $this->finding(
					isset( $database_users[ $user_id ] ) && $this->is_privileged( $user_id ) ? 'high' : 'medium',
					'Session expires far beyond the WordPress maximum',
					$long_lived . ' session token(s) expire more than 15 days from now. WordPress issues sessions for at most 14 days unless an auth_cookie_expiration filter extends them. Token data was not returned by the scan.',
					'Review auth_cookie_expiration callbacks, destroy unrecognized sessions, and investigate direct metadata manipulation.',
					$user_id,
					isset( $database_users[ $user_id ] ) ? (string) $database_users[ $user_id ]['user_login'] : ''
				);
			}

			if ( $future_login ) {
				$findings[] = $this->finding(
					'high',
					'Session login time is in the future',
					$future_login . ' session token(s) record a login time more than one day ahead of the current time. Token data was not returned by the scan.',
					'Review server time settings, destroy unrecognized sessions, and investigate direct metadata manipulation.',
					$user_id,
					isset( $database_users[ $user_id ] ) ? (string) $database_users[ $user_id ]['user_login'] : ''
				);
			}

			if ( ! isset( $database_users[ $user_id ] ) ) {
				$findings[] = $this->finding(
					'high',
					'Session metadata references a missing user',
					'Stored session metadata exists without a matching account.',
					'Preserve the row and remove it only after confirming the account deletion.',
					$user_id
				);
			} elseif ( $count >= 10 ) {
				$findings[] = $this->finding(
					'high',
					'User has many active sessions',
					'The account has ' . $count . ' unexpired WordPress sessions.',
					'Validate the account owner and destroy sessions that are not recognized.',
					$user_id,
					(string) $database_users[ $user_id ]['user_login']
				);
			} elseif ( $count >= 5 && $this->is_privileged( $user_id ) ) {
				$findings[] = $this->finding(
					'medium',
					'Privileged user has several active sessions',
					'The account has ' . $count . ' unexpired WordPress sessions.',
					'Confirm the sessions are expected and enforce multi-factor authentication.',
					$user_id,
					(string) $database_users[ $user_id ]['user_login']
				);
			}
		}

		foreach ( $application_rows as $row ) {
			$user_id = (int) $row['user_id'];

			if ( ! $this->in_scope( $user_id ) ) {
				continue;
			}

			$passwords                              = $this->safe_unserialize( (string) $row['meta_value'] );
			$application_rows_by_user[ $user_id ][] = $row;

			if ( ! is_array( $passwords ) ) {
				$findings[] = $this->finding(
					'high',
					'Application-password metadata is malformed',
					'The application-password value is not a valid serialized array. Credential data was not returned by the scan.',
					'Preserve the row and investigate direct metadata manipulation.',
					$user_id,
					isset( $database_users[ $user_id ] ) ? (string) $database_users[ $user_id ]['user_login'] : ''
				);
			}

			$count                  = is_array( $passwords ) ? count( $passwords ) : 0;
			$application_passwords += $count;

			if ( $count > 0 && ! isset( $database_users[ $user_id ] ) ) {
				$findings[] = $this->finding(
					'high',
					'Application passwords reference a missing user',
					'Stored application-password records exist without a matching account. Credential values were not read or returned.',
					'Preserve the row and remove it only after confirming the account deletion.',
					$user_id
				);
			} elseif ( $count > 0 ) {
				$findings[] = $this->finding(
					isset( $database_users[ $user_id ] ) && $this->is_privileged( $user_id ) ? 'medium' : 'informational',
					'Application passwords are configured',
					'The account has ' . $count . ' application password record(s). Credential values were not read or returned.',
					'Confirm every integration and revoke credentials that are no longer required.',
					$user_id,
					isset( $database_users[ $user_id ] ) ? (string) $database_users[ $user_id ]['user_login'] : ''
				);
			}
		}

		foreach ( $session_rows_by_user as $user_id => $user_session_rows ) {
			if ( count( $user_session_rows ) > 1 ) {
				$findings[] = $this->finding(
					'medium',
					'User has duplicate session metadata rows',
					'The account has ' . count( $user_session_rows ) . ' session_tokens rows.',
					'Preserve the rows and determine how duplicate session storage was created.',
					$user_id,
					isset( $database_users[ $user_id ] ) ? (string) $database_users[ $user_id ]['user_login'] : ''
				);
			}
		}

		foreach ( $application_rows_by_user as $user_id => $user_application_rows ) {
			if ( count( $user_application_rows ) > 1 ) {
				$findings[] = $this->finding(
					'medium',
					'User has duplicate application-password metadata rows',
					'The account has ' . count( $user_application_rows ) . ' application-password rows.',
					'Preserve the rows and determine how duplicate credential storage was created.',
					$user_id,
					isset( $database_users[ $user_id ] ) ? (string) $database_users[ $user_id ]['user_login'] : ''
				);
			}
		}

		return array(
			'findings' => $findings,
			'metrics'  => array(
				'session_meta_rows'     => array_sum( array_map( 'count', $session_rows_by_user ) ),
				'active_sessions'       => $active_sessions,
				'application_passwords' => $application_passwords,
			),
		);
	}

	/**
	 * Reviews email, registration, status, password-hash, and username anomalies.
	 *
	 * @return array{findings:array<int,array<string,mixed>>,metrics:array<string,int|string>}
	 */
	private function test_identity(): array {
		$rows     = $this->scoped_users();
		$findings = array();
		$emails   = array();
		$now      = time();

		$password_hashes = array();

		foreach ( array_chunk( array_map( static fn ( array $row ): int => (int) $row['ID'], $rows ), 1000 ) as $id_chunk ) {
			$password_hashes += array_column(
				$this->direct_rows(
					$this->wpdb->prepare(
						'SELECT ID, user_pass FROM %i WHERE ID IN (' . implode( ', ', array_fill( 0, count( $id_chunk ), '%d' ) ) . ')',
						array_merge( array( $this->wpdb->users ), $id_chunk )
					)
				),
				'user_pass',
				'ID'
			);
		}

		foreach ( $rows as $row ) {
			$user_id       = (int) $row['ID'];
			$is_privileged = $this->is_privileged( $user_id );
			$email         = strtolower( trim( (string) $row['user_email'] ) );

			if ( '' === $email || false === filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
				$findings[] = $this->finding(
					$is_privileged ? 'high' : 'low',
					'User has a missing or invalid email address',
					'The account cannot be reliably associated with a valid email identity.',
					'Confirm the account owner and correct the email only through an approved account-management process.',
					$user_id,
					(string) $row['user_login']
				);
			} else {
				$emails[ $email ][] = $row;
			}

			$registered = strtotime( (string) $row['user_registered'] . ' UTC' );

			if ( false === $registered || str_starts_with( (string) $row['user_registered'], '0000-00-00' ) ) {
				$findings[] = $this->finding(
					'medium',
					'User has an invalid registration timestamp',
					'The account registration date is missing or invalid.',
					'Confirm the account history and determine whether the row was inserted outside normal WordPress APIs.',
					$user_id,
					(string) $row['user_login']
				);
			} elseif ( $registered > $now + DAY_IN_SECONDS ) {
				$findings[] = $this->finding(
					'high',
					'User registration date is in the future',
					'The account timestamp is more than one day ahead of the current UTC time.',
					'Review database time settings and investigate direct row manipulation.',
					$user_id,
					(string) $row['user_login']
				);
			}

			if ( 0 !== (int) $row['user_status'] ) {
				$findings[] = $this->finding(
					'low',
					'User has a non-zero status value',
					'The account user_status value is ' . (int) $row['user_status'] . '.',
					'Confirm whether a plugin intentionally uses this field.',
					$user_id,
					(string) $row['user_login']
				);
			}

			$password_hash = (string) ( $password_hashes[ $user_id ] ?? '' );

			if ( '' === $password_hash ) {
				$findings[] = $this->finding(
					'critical',
					'User has an empty password hash',
					'The users-table password field is empty. The hash value was not returned by the scan.',
					'Confirm the account owner and reset or disable the account through an approved process.',
					$user_id,
					(string) $row['user_login']
				);
			} elseif ( preg_match( '/^[a-f0-9]{32}$/i', $password_hash ) ) {
				$findings[] = $this->finding(
					$is_privileged ? 'high' : 'medium',
					'User has a legacy unsalted MD5 password hash',
					'The password field matches the legacy 32-character MD5 format. The hash value was not returned by the scan.',
					'Require a password reset so WordPress can replace the legacy hash after successful authentication.',
					$user_id,
					(string) $row['user_login']
				);
			} elseif ( ! $this->is_recognized_password_hash( $password_hash ) ) {
				$findings[] = $this->finding(
					'high',
					'User has an unrecognized password hash format',
					'The password field does not match a recognized WordPress, bcrypt, or Argon2 hash prefix. The value was not returned by the scan.',
					'Preserve the row and determine whether authentication code or the database was modified.',
					$user_id,
					(string) $row['user_login']
				);
			}

			if ( $is_privileged && preg_match( '/^[a-z]{6,}[0-9]{4,}$/i', (string) $row['user_login'] ) ) {
				$findings[] = $this->finding(
					'medium',
					'Privileged username matches a generated-name pattern',
					'The username combines a long letter sequence and four or more trailing digits.',
					'Treat the pattern only as a heuristic and validate the account owner and creation history.',
					$user_id,
					(string) $row['user_login']
				);
			}

			if ( $is_privileged ) {
				$login           = (string) $row['user_login'];
				$login_anomalies = array();

				if ( trim( (string) preg_replace( '/\s+/', ' ', $login ) ) !== $login ) {
					$login_anomalies[] = 'leading, trailing, repeated, or non-space whitespace';
				}

				if ( preg_match( '/[\x00-\x1F\x7F]/', $login ) || 1 === preg_match( '/\p{Cf}/u', $login ) ) {
					$login_anomalies[] = 'control or invisible characters';
				}

				if ( preg_match( '/[^\x00-\x7F]/', $login ) ) {
					$login_anomalies[] = 'non-ASCII characters that can imitate another login';
				}

				if ( $login_anomalies ) {
					$findings[] = $this->finding(
						'high',
						'Privileged username contains hidden or lookalike characters',
						'The login contains ' . implode( '; ', $login_anomalies ) . '. WordPress removes these characters when it creates accounts, so the row was likely written outside normal account APIs.',
						'Compare the login byte by byte with known administrator accounts, validate the account owner, and investigate how the row was created.',
						$user_id,
						$login
					);
				}
			}

			if ( $is_privileged && in_array( strtolower( (string) $row['user_login'] ), array( 'admin', 'administrator', 'root', 'support', 'test', 'wordpress' ), true ) ) {
				$findings[] = $this->finding(
					'low',
					'Privileged account uses a commonly targeted username',
					'The login name is commonly attempted in automated credential attacks.',
					'Require multi-factor authentication, a unique strong password, and monitoring for failed logins.',
					$user_id,
					(string) $row['user_login']
				);
			}
		}

		foreach ( $emails as $email_rows ) {
			if ( count( $email_rows ) < 2 ) {
				continue;
			}

			$ids        = array_map( static fn ( array $row ): int => (int) $row['ID'], $email_rows );
			$findings[] = $this->finding(
				'medium',
				'Multiple users share the same email address',
				'The same normalized email is assigned to user IDs ' . implode( ', ', array_map( 'strval', $ids ) ) . '. The email value is not displayed.',
				'Confirm that the accounts are intentionally shared and preserve distinct accountability for privileged access.'
			);
		}

		$clusters = $this->registration_clusters( $rows );

		foreach ( $clusters as $cluster ) {
			$privileged_ids = array_values(
				array_filter(
					array_map( static fn ( array $row ): int => (int) $row['ID'], $cluster ),
					fn ( int $user_id ): bool => $this->is_privileged( $user_id )
				)
			);
			$findings[]     = $this->finding(
				$privileged_ids ? 'medium' : 'informational',
				$privileged_ids ? 'Registration cluster includes privileged accounts' : 'Multiple accounts were registered in a short interval',
				count( $cluster ) . ' accounts were registered within 15 minutes. IDs: ' . implode( ', ', array_map( static fn ( array $row ): string => (string) $row['ID'], $cluster ) ) . ( $privileged_ids ? '. Privileged IDs: ' . implode( ', ', array_map( 'strval', $privileged_ids ) ) : '' ) . '.',
				'Determine whether the cluster reflects a legitimate import, checkout activity, or automated account creation.'
			);
		}

		return array(
			'findings' => $findings,
			'metrics'  => array(
				'users_reviewed'        => count( $rows ),
				'duplicate_email_sets'  => count( array_filter( $emails, static fn ( array $items ): bool => count( $items ) > 1 ) ),
				'registration_clusters' => count( $clusters ),
			),
		);
	}

	/**
	 * Scans one batch of code for user-related paths.
	 *
	 * @return array{findings:array<int,array<string,mixed>>,metrics:array<string,int|string>,code_paths:array<int,array<string,mixed>>,next:array{root:int,path:string}|null}
	 */
	private function test_code_paths(): array {
		$roots                  = $this->active_code_roots();
		$findings               = array();
		$code_paths             = array();
		$scanned_files          = 0;
		$batch_bytes            = 0;
		$root_index             = max( 0, (int) ( $this->cursor['root'] ?? 0 ) );
		$resume_path            = (string) ( $this->cursor['path'] ?? '' );
		$next                   = null;
		$database_users         = $this->database_users_by_id();
		$capability_key_pattern = '/(?:\b' . preg_quote( $this->wpdb->base_prefix, '/' ) . '(?:\d+_)?capabilities\b|prefix(?:\s*\([^)]*\))?\s*\.\s*[\'"]capabilities[\'"])/';
		$patterns               = array(
			'pre_get_users'               => 'Changes user-query arguments',
			'pre_user_query'              => 'Filters WordPress user queries',
			'users_pre_query'             => 'Can replace WordPress user-query results',
			'users_list_table_query_args' => 'Changes the Users-screen query',
			'views_users'                 => 'Changes Users-screen views or counts',
			'pre_count_users'             => 'Can replace Users-screen role counts',
			'rest_user_query'             => 'Changes REST API user-query arguments',
			'editable_roles'              => 'Can hide roles from administration',
			'user_has_cap'                => 'Can alter runtime user capabilities',
			'map_meta_cap'                => 'Can alter runtime capability mapping',
			'site_option_site_admins'     => 'Can alter the network super administrator list',
			'pre_site_option_site_admins' => 'Can replace the network super administrator list',
			'wp_insert_user'              => 'Creates or updates WordPress users',
			'wp_create_user'              => 'Creates WordPress users',
			'add_cap'                     => 'Adds capabilities',
			'set_role'                    => 'Changes user roles',
			'wp_set_auth_cookie'          => 'Signs a user in without the login form',
			'wp_set_current_user'         => 'Switches the current user without the login form',
			'wp_signon'                   => 'Signs a user in without the login form',
			'determine_current_user'      => 'Can swap the identity of the current request',
		);

		foreach ( array_slice( $roots, $root_index, null, true ) as $index => $root ) {
			$last_path  = $index === $root_index ? $resume_path : '';
			$root_kind  = $this->root_kinds[ $root ] ?? 'active';
			$code_label = 'inactive' === $root_kind ? 'Inactive' : 'Active';

			foreach ( $this->code_files( $root, $last_path ) as $file ) {
				if ( $scanned_files >= self::CODE_BATCH_FILES || $batch_bytes >= self::CODE_BATCH_BYTES ) {
					$next = array(
						'root' => $index,
						'path' => $last_path,
					);
					break 2;
				}

				$last_path = ltrim( substr( str_replace( '\\', '/', $file->getPathname() ), strlen( untrailingslashit( str_replace( '\\', '/', $root ) ) ) ), '/' );
				++$scanned_files;

				$batch_bytes += $file->isLink() ? 0 : min( (int) $file->getSize(), self::MAX_PHP_FILE_BYTES );

				if ( $file->isLink() ) {
					$findings[] = $this->symlink_finding( $file->getPathname(), $root_kind );
					continue;
				}

				if ( $file->isDir() ) {
					$findings[] = $this->finding(
						'uploads' === $root_kind ? 'high' : 'medium',
						'Directory could not be read and was not scanned',
						'Directory: ' . $this->relative_path( $file->getPathname() ) . '. Files inside it were not checked for user-related code.',
						'Confirm the directory permissions are intentional, then scan its contents with an account that can read them.'
					);
					continue;
				}

				if ( in_array( strtolower( $file->getExtension() ), self::PHP_EXTENSIONS, true ) && 'uploads' === $root_kind ) {
					$findings[] = $this->finding(
						'high',
						'PHP file exists in the uploads folder',
						'File: ' . $this->relative_path( $file->getPathname() ) . '. PHP in the uploads folder is a common webshell indicator, whatever the file contains.',
						'Preserve the file, confirm whether any plugin legitimately writes PHP there, and block PHP execution in the uploads folder.'
					);
				} elseif ( in_array( strtolower( $file->getExtension() ), self::PHP_EXTENSIONS, true ) && 'content' === $root_kind ) {
					$findings[] = $this->finding(
						'medium',
						'Unknown PHP file in the wp-content folder',
						'File: ' . $this->relative_path( $file->getPathname() ) . '. The file is not a WordPress drop-in.',
						'Confirm which plugin or deployment created the file and remove it if it is not required.'
					);
				}
				if ( in_array( strtolower( $file->getExtension() ), self::PHP_EXTENSIONS, true ) && $file->getSize() > self::MAX_PHP_FILE_BYTES ) {
					$findings[] = $this->finding(
						'medium',
						'Oversized PHP file was not scanned',
						'File: ' . $this->relative_path( $file->getPathname() ) . '. The file is ' . $file->getSize() . ' bytes, above the ' . self::MAX_PHP_FILE_BYTES . '-byte scan limit. Large PHP files are uncommon and can contain packed or obfuscated code.',
						'Inspect the file manually or with an offline scanner.'
					);
					continue;
				}

				if ( $this->is_server_config_file( $file ) ) {
					$config_contents = file_get_contents( $file->getPathname(), false, null, 0, self::MAX_CODE_FILE_BYTES ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads a local file.
					$site_root       = trailingslashit( str_replace( '\\', '/', dirname( $file->getPathname() ) ) ) === trailingslashit( str_replace( '\\', '/', ABSPATH ) );

					foreach ( false === $config_contents ? array() : $this->server_config_directives( $config_contents, $site_root ) as $directive ) {
						$findings[] = $this->finding(
							$directive['severity'],
							'Server configuration file changes how PHP runs',
							'File: ' . $this->relative_path( $file->getPathname() ) . '. ' . $directive['detail'] . '.',
							'Confirm the directive belongs to the host or an approved tool, such as a web application firewall, and remove it if it does not.'
						);
					}

					continue;
				}

				if ( 'uploads' === $root_kind && ! in_array( strtolower( $file->getExtension() ), array_merge( self::PHP_EXTENSIONS, array( 'css', 'js' ) ), true ) ) {
					$head = file_get_contents( $file->getPathname(), false, null, 0, self::MAX_CODE_FILE_BYTES ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads a local file.

					if ( false !== $head && preg_match( '/<\?php\b/i', $head ) ) {
						$findings[] = $this->finding(
							'high',
							'PHP code is hidden in a non-PHP file in the uploads folder',
							'File: ' . $this->relative_path( $file->getPathname() ) . '. The file contains a PHP open tag. Webshells hide PHP in images and text files and run it through an include or a server handler.',
							'Preserve the file, search the code base for anything that includes or requires it, and remove it after evidence review.'
						);
					}

					continue;
				}

				$contents = file_get_contents( $file->getPathname() ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads a local file.

				if ( false === $contents ) {
					continue;
				}

				$matches   = array();
				$extension = strtolower( $file->getExtension() );

				if ( in_array( $extension, self::PHP_EXTENSIONS, true ) ) {
					foreach ( $patterns as $needle => $description ) {
						if ( false !== strpos( $contents, $needle ) && preg_match( '/\b' . preg_quote( $needle, '/' ) . '\b/', $contents ) ) {
							$matches[ $needle ] = $description;
						}
					}
					if ( preg_match( $capability_key_pattern, $contents ) ) {
						$matches['capability_meta_key'] = 'References capability metadata directly';
					}
					if ( preg_match( '/add_(?:filter|action)\s*\(\s*[\'\"]query[\'\"]/i', $contents ) ) {
						$matches['query_filter'] = 'Can rewrite wpdb queries globally';
					}

					if ( preg_match_all( '/add_(?:filter|action)\s*\(\s*[\'\"](authenticate|check_password|wp_authenticate_user)[\'\"]/i', $contents, $credential_hooks ) ) {
						foreach ( array_unique( array_map( 'strtolower', $credential_hooks[1] ) ) as $credential_hook ) {
							$matches[ $credential_hook ] = 'Can bypass or replace credential checks';
						}
					}

					if ( preg_match( '/(?:->insert\s*\(\s*\$wpdb->users|INSERT\s+INTO\s+[`\'\"]?[^\s]+users\b)/i', $contents ) ) {
						$matches['direct_user_table_write'] = 'Writes directly to the users table';
					}

					if ( preg_match( '/->(?:insert|replace|update)\s*\(\s*\$wpdb->usermeta/i', $contents ) ) {
						$matches['direct_usermeta_write'] = 'Writes directly to the usermeta table';
					}
				}

				$matches = array_merge( $matches, $this->users_screen_hiding_patterns( $contents, $extension ) );

				if ( ! $matches ) {
					continue;
				}

				$relative_path = $this->relative_path( $file->getPathname() );
				$code_paths[]  = array(
					'path'     => $relative_path,
					'patterns' => array_keys( $matches ),
				);

				$hides_users             = isset( $matches['pre_get_users'] )
					|| isset( $matches['pre_user_query'] )
					|| isset( $matches['users_pre_query'] )
					|| isset( $matches['users_list_table_query_args'] )
					|| isset( $matches['views_users'] )
					|| isset( $matches['pre_count_users'] )
					|| isset( $matches['rest_user_query'] );
				$hides_user_rows         = isset( $matches['users_screen_css_hide'] ) || isset( $matches['users_screen_script_hide'] ) || isset( $matches['users_screen_count_rewrite'] );
				$authenticates_directly  = isset( $matches['wp_set_auth_cookie'] )
					|| isset( $matches['wp_set_current_user'] )
					|| isset( $matches['wp_signon'] )
					|| isset( $matches['determine_current_user'] )
					|| isset( $matches['authenticate'] )
					|| isset( $matches['check_password'] )
					|| isset( $matches['wp_authenticate_user'] );
				$changes_runtime_access  = isset( $matches['user_has_cap'] ) || isset( $matches['map_meta_cap'] ) || isset( $matches['site_option_site_admins'] ) || isset( $matches['pre_site_option_site_admins'] );
				$creates_users           = isset( $matches['wp_insert_user'] ) || isset( $matches['wp_create_user'] );
				$request_controlled      = preg_match( '/\$_(?:GET|POST|REQUEST|COOKIE)\b/', $contents ) === 1;
				$direct_capability_write = isset( $matches['capability_meta_key'] ) && preg_match( '/(?:update|add)_user_meta\s*\(/', $contents );
				$file_finding_count      = count( $findings );

				if ( $hides_user_rows ) {
					$findings[] = $this->finding(
						'high',
						$code_label . ' CSS or JavaScript may hide users from the Users screen',
						'File: ' . $relative_path . '. Matched: ' . implode( ', ', array_keys( $matches ) ) . '. Static matching does not prove malicious intent.',
						'Inspect the selector and hide/remove logic, then compare the rendered Users screen with the direct database inventory.'
					);

					foreach ( $this->users_screen_targeted_user_ids( $contents ) as $targeted_user_id ) {
						if ( ! isset( $database_users[ $targeted_user_id ] ) ) {
							continue;
						}

						$access                     = $this->database_user_access( $targeted_user_id );
						$administrator_capabilities = array_values( array_intersect( self::CRITICAL_CAPABILITIES, $access['effective'] ) );
						$has_administrator_role     = in_array( 'administrator', $access['roles'], true );
						$privileged                 = $has_administrator_role || $administrator_capabilities || ( 'network' === $this->scope && $this->is_privileged( $targeted_user_id ) );

						$findings[] = $this->finding(
							$privileged ? 'critical' : 'high',
							$privileged ? 'CSS or JavaScript targets a privileged user for hiding' : 'CSS or JavaScript targets a user row for hiding',
							'File: ' . $relative_path . '. The hiding selector targets database user ID ' . $targeted_user_id . ( $privileged ? ', which has administrator-level access.' : '.' ),
							$privileged ? 'Treat this as potential account-concealment persistence and investigate immediately.' : 'Validate the account and confirm why its row is intentionally hidden.',
							$targeted_user_id,
							(string) $database_users[ $targeted_user_id ]['user_login']
						);
					}
				}

				if ( isset( $matches['query_filter'] ) ) {
					$findings[] = $this->finding(
						'high',
						$code_label . ' code can rewrite WordPress database queries',
						'File: ' . $relative_path . '. ' . ( null === $this->database ? 'The validation evidence queries ran through wpdb and are subject to this filter.' : 'The validation evidence queries bypass this filter.' ),
						'Review the callback for data hiding, credential capture, and unauthorized query modification.'
					);
				}

				if ( isset( $matches['direct_user_table_write'] ) || isset( $matches['direct_usermeta_write'] ) ) {
					$table_write_severity = isset( $matches['direct_user_table_write'] ) || $request_controlled ? 'high' : 'medium';
					$findings[]           = $this->finding(
						$table_write_severity,
						$code_label . ' code writes directly to user database tables',
						'File: ' . $relative_path . '. Matched: ' . implode( ', ', array_keys( $matches ) ) . '. Static matching does not prove malicious intent.',
						'Review authorization, transaction safety, audit logging, and why WordPress account APIs are bypassed.'
					);
				}

				if ( $hides_users ) {
					$findings[] = $this->finding(
						'medium',
						$code_label . ' code can modify user-query visibility',
						'File: ' . $relative_path . '. Matched: ' . implode( ', ', array_keys( $matches ) ) . '.',
						'Review the callback intent. An actual database-versus-query discrepancy is reported separately at high or critical severity.'
					);
				}

				if ( $authenticates_directly ) {
					$hard_coded_identity = $this->has_hard_coded_identity( $contents );

					if ( $hard_coded_identity ) {
						$authentication_severity = 'critical';
					} elseif ( $request_controlled ) {
						$authentication_severity = 'high';
					} else {
						$authentication_severity = 'medium';
					}

					$findings[] = $this->finding(
						$authentication_severity,
						$code_label . ( $hard_coded_identity ? ' code signs users in with a hard-coded identity or password' : ' code can sign users in or bypass credential checks' ),
						'File: ' . $relative_path . '. Matched: ' . implode( ', ', array_keys( $matches ) ) . '.' . ( $hard_coded_identity ? ' The file also contains a hard-coded user ID, login, or request-value comparison.' : '' ) . ' Static matching does not prove malicious intent; single sign-on, two-factor, and login plugins use these hooks legitimately.',
						'Review which accounts the code can sign in, the request conditions that trigger it, and whether a master password or magic link is present.'
					);
				}

				if ( $changes_runtime_access ) {
					$runtime_severity = $request_controlled ? 'medium' : 'informational';

					$findings[] = $this->finding(
						$runtime_severity,
						$code_label . ' code can change runtime user authorization',
						'File: ' . $relative_path . '. Matched: ' . implode( ', ', array_keys( $matches ) ) . '. Database capability records may not show runtime-only grants.',
						'Review callback conditions, caller control, and whether protected capabilities can be granted dynamically.'
					);
				}

				if ( $direct_capability_write ) {
					$findings[] = $this->finding(
						'high',
						$code_label . ' code may write capability metadata directly',
						'File: ' . $relative_path . '.',
						'Review authorization, nonce validation, and whether the code bypasses WordPress role APIs.'
					);
				}

				if ( $creates_users && $request_controlled ) {
					$findings[] = $this->finding(
						'medium',
						'Request-handling code can create users',
						'File: ' . $relative_path . '. Static pattern matching does not prove missing authorization.',
						'Review capability checks, nonce validation, input validation, and intended exposure.'
					);
				}

				if ( count( $findings ) === $file_finding_count ) {
					$findings[] = $this->finding(
						'informational',
						$code_label . ' code contains a user-management path',
						'File: ' . $relative_path . '. Matched: ' . implode( ', ', array_keys( $matches ) ) . '.',
						'Review this path when investigating unexpected user creation or role changes.'
					);
				}
			}
		}

		if ( 0 === $root_index && '' === $resume_path ) {
			$findings = array_merge( $findings, $this->root_findings );
		}

		return array(
			'findings'   => $this->deduplicate_findings( $findings ),
			'metrics'    => array(
				'roots_reviewed'      => count( $roots ),
				'files_scanned'       => $scanned_files,
				'matched_files'       => count( $code_paths ),
				'evidence_connection' => null === $this->database ? 'wpdb' : 'mysqli',
			),
			'code_paths' => array_slice( $code_paths, 0, 100 ),
			'next'       => $next,
		);
	}

	/**
	 * Checks whether registration is enabled and whether the default role grants administrator-level access.
	 *
	 * @return array{findings:array<int,array<string,mixed>>,metrics:array<string,int|string>}
	 */
	private function test_registration(): array {
		$findings            = array();
		$registration_mode   = '';
		$default_role_value  = $this->database_option_value( 'default_role' );
		$default_role        = '' !== $default_role_value ? $default_role_value : 'subscriber';
		$default_role_object = $this->role_definitions[ $default_role ] ?? null;

		if ( is_array( $default_role_object ) ) {
			$default_granted   = array_keys( array_filter( (array) ( $default_role_object['capabilities'] ?? array() ) ) );
			$default_critical  = array_values( array_intersect( $default_granted, self::CRITICAL_CAPABILITIES ) );
			$default_sensitive = array_values( array_intersect( $default_granted, self::SENSITIVE_CAPABILITIES ) );

			if ( $default_critical ) {
				$findings[] = $this->finding(
					'critical',
					'Default registration role grants administrator-level access',
					'New users receive role "' . $default_role . '" with critical capabilities.',
					'Disable public registration if enabled and restore a least-privilege default role immediately.'
				);
			} elseif ( $default_sensitive ) {
				$findings[] = $this->finding(
					'high',
					'Default registration role grants sensitive capabilities',
					'New users receive role "' . $default_role . '" with: ' . $this->bounded_list( $default_sensitive ) . '.',
					'Confirm each capability is required for new accounts and restore a least-privilege default role if it is not.'
				);
			}
		} else {
			$findings[] = $this->finding(
				'medium',
				'Default registration role does not exist',
				'The default_role option is "' . $default_role . '", which is not defined in the raw role option. New accounts receive that role key and gain its access if a role with that name is later defined.',
				'Restore a defined least-privilege default role and review accounts created while the option was set.'
			);
		}

		// Multisite ignores users_can_register and uses the network registration option instead.
		if ( is_multisite() ) {
			$registration_mode    = $this->database_network_option_value( 'registration' );
			$registration_mode    = in_array( $registration_mode, array( 'none', 'user', 'blog', 'all' ), true ) ? $registration_mode : 'none';
			$registration_enabled = in_array( $registration_mode, array( 'user', 'all' ), true );
		} else {
			$registration_enabled = '1' === $this->database_option_value( 'users_can_register' );
		}

		$metrics = array(
			'registration_enabled' => $registration_enabled ? 'yes' : 'no',
			'default_role'         => $default_role,
		);

		if ( is_multisite() ) {
			$metrics['registration_mode'] = $registration_mode;
		}

		return array(
			'findings' => $findings,
			'metrics'  => $metrics,
		);
	}

	/**
	 * Reviews super administrators, network-wide visibility, unassigned users, and orphaned metadata.
	 *
	 * @return array{findings:array<int,array<string,mixed>>,metrics:array<string,int|string>}
	 */
	private function test_network_integrity(): array {
		global $super_admins;

		$findings       = array();
		$database_rows  = $this->database_users();
		$logins         = $this->super_admin_logins();
		$users_by_login = array();

		foreach ( $database_rows as $row ) {
			$users_by_login[ (string) $row['user_login'] ] = $row;
		}

		if ( isset( $super_admins ) ) {
			$findings[] = $this->finding(
				'high',
				'Super administrators are defined in code',
				'The $super_admins global is set, so WordPress ignores the site_admins network option. Logins defined in code: ' . ( $logins ? $this->bounded_list( $logins ) : 'none' ) . '.',
				'Locate where the global is defined, usually wp-config.php, confirm every listed account, and remove the override unless it is an approved configuration.'
			);
		}

		if ( has_filter( 'site_option_site_admins' ) || has_filter( 'pre_site_option_site_admins' ) ) {
			$runtime_logins = array_values( array_filter( (array) get_super_admins(), 'is_string' ) );
			$gained         = array_values( array_diff( $runtime_logins, $logins ) );
			$lost           = array_values( array_diff( $logins, $runtime_logins ) );

			$findings[] = $this->finding(
				$gained || $lost ? 'high' : 'informational',
				$gained || $lost ? 'Super administrator list differs at runtime' : 'Super administrator option filters are active',
				'One or more active callbacks filter the site_admins network option.' . ( $gained ? ' Added at runtime: ' . $this->bounded_list( $gained ) . '.' : '' ) . ( $lost ? ' Removed at runtime: ' . $this->bounded_list( $lost ) . '.' : '' ) . ( $gained || $lost ? '' : ' No issue is implied when the runtime list matches the stored list.' ),
				'Review the site_admins option callbacks and confirm every super administrator WordPress enforces with the site owner.'
			);
		}

		$roles_global_finding = $this->user_roles_global_finding();

		if ( null !== $roles_global_finding ) {
			$findings[] = $roles_global_finding;
		}

		foreach ( $logins as $login ) {
			$row = $users_by_login[ $login ] ?? null;

			$findings[] = $this->finding(
				is_array( $row ) ? 'informational' : 'high',
				is_array( $row ) ? 'Network super administrator requires ownership review' : 'Network super administrator references a missing user',
				is_array( $row ) ? 'The account is listed as a network super administrator.' : 'The super administrator list contains a login absent from the users table.',
				'Confirm every network administrator with the site owner and enforce multi-factor authentication.',
				is_array( $row ) ? (int) $row['ID'] : 0,
				is_array( $row ) ? (string) $row['user_login'] : $login
			);
		}

		$database_ids   = array_map( 'intval', array_column( $database_rows, 'ID' ) );
		$query          = new WP_User_Query(
			array(
				'blog_id'     => 0,
				'fields'      => 'ID',
				'number'      => -1,
				'count_total' => false,
			)
		);
		$query_ids      = array_map( 'intval', $query->get_results() );
		$missing_ids    = array_values( array_diff( $database_ids, $query_ids ) );
		$unexpected_ids = array_values( array_diff( $query_ids, $database_ids ) );

		foreach ( $missing_ids as $user_id ) {
			$row        = $this->find_database_user( $database_rows, $user_id );
			$privileged = $this->is_privileged( $user_id );

			$findings[] = $this->finding(
				$privileged ? 'critical' : 'high',
				$privileged ? 'Hidden user has privileged access on the network' : 'Database user is hidden from network-wide user queries',
				'The account exists in the users table but is absent from a network-wide WP_User_Query result.',
				$privileged ? 'Treat this as a potential persistence account. Preserve evidence, validate ownership, and inspect every user-list filter before containment.' : 'Inspect active pre_user_query and users_pre_query filters and validate the account owner.',
				$user_id,
				(string) ( $row['user_login'] ?? '' )
			);
		}

		if ( $unexpected_ids ) {
			$findings[] = $this->finding(
				'high',
				'WordPress returned users absent from the users table',
				'Network-wide user queries returned unexpected IDs: ' . implode( ', ', array_map( 'strval', array_slice( $unexpected_ids, 0, 20 ) ) ) . '.',
				'Review object caching, user-query filters, and database consistency.'
			);
		}

		$network_screen     = $this->in_users_screen(
			'users-network',
			fn (): array => array(
				'ids'   => $this->users_screen_query_ids(
					array(
						'number'  => 25,
						'offset'  => 0,
						'search'  => '',
						'blog_id' => 0,
						'fields'  => 'all_with_meta',
					)
				),
				'views' => $this->filtered_view_changes(
					'views_users-network',
					array(
						'all'   => (int) get_user_count(),
						'super' => count( get_super_admins() ),
					)
				),
			)
		);
		$screen_missing_ids = array_values( array_diff( $database_ids, $network_screen['ids'], $missing_ids ) );

		foreach ( $screen_missing_ids as $user_id ) {
			$row        = $this->find_database_user( $database_rows, $user_id );
			$privileged = $this->is_privileged( $user_id );

			$findings[] = $this->finding(
				$privileged ? 'critical' : 'high',
				$privileged ? 'Network Users screen hides a privileged user' : 'Network Users screen hides a database user',
				'The account exists in the users table and in network-wide user queries, but is absent from the network Users-screen query.',
				'Inspect active users_list_table_query_args, pre_get_users, and pre_user_query callbacks, including ones that only run on the network Users screen, and validate the account owner.',
				$user_id,
				(string) ( $row['user_login'] ?? '' )
			);
		}

		if ( $network_screen['views'] ) {
			$findings[] = $this->finding(
				'high',
				'Network Users-screen views are altered by a filter',
				'The views_users-network filter changed the views: ' . $this->bounded_list( $network_screen['views'] ) . '.',
				'Inspect active views_users-network callbacks and compare the network Users screen with the direct database inventory.'
			);
		}

		$members         = $this->network_access()['members'];
		$super_admin_ids = $this->super_admin_ids();
		$unassigned      = 0;

		foreach ( $database_rows as $row ) {
			$user_id = (int) $row['ID'];

			if ( isset( $members[ $user_id ] ) || isset( $super_admin_ids[ $user_id ] ) ) {
				continue;
			}

			++$unassigned;
			$findings[] = $this->finding(
				'low',
				'User belongs to no network site',
				'The account has no capability record on any site in the network.',
				'Confirm that the account is intentionally unassigned.',
				$user_id,
				(string) $row['user_login']
			);
		}

		$orphan_rows = $this->orphan_meta_rows();

		if ( $orphan_rows > 0 ) {
			$findings[] = $this->finding(
				'medium',
				'Orphaned user metadata exists',
				$orphan_rows . ' usermeta rows do not have a matching users-table record.',
				'Review the metadata keys and remove records only after evidence and ownership review.'
			);
		}

		return array(
			'findings' => $findings,
			'metrics'  => array(
				'super_admins'              => count( $logins ),
				'code_defined_super_admins' => isset( $super_admins ) ? 'yes' : 'no',
				'code_defined_roles'        => null !== $roles_global_finding ? 'yes' : 'no',
				'database_users'            => count( $database_ids ),
				'query_users'               => count( $query_ids ),
				'hidden_users'              => count( $missing_ids ),
				'screen_hidden_users'       => count( $screen_missing_ids ),
				'altered_views'             => count( $network_screen['views'] ),
				'unassigned_users'          => $unassigned,
				'orphan_meta_rows'          => $orphan_rows,
			),
		);
	}

	/**
	 * Executes a read-only query on WordPress's existing mysqli connection.
	 * This intentionally bypasses wpdb::query() and its global query filter.
	 * When a drop-in replaces the mysqli connection it falls back to wpdb, whose queries are filterable.
	 *
	 * @param string $query Read-only SELECT or SHOW statement, already prepared.
	 * @return array<int,array<string,mixed>>
	 * @throws RuntimeException When the statement is not read-only or the query fails.
	 */
	private function direct_rows( string $query ): array {
		if ( ! preg_match( '/^\s*(?:SELECT|SHOW)\b/i', $query ) ) {
			throw new RuntimeException( 'Only read-only validation queries are permitted.' );
		}

		$query = $this->wpdb->remove_placeholder_escape( $query );

		if ( null === $this->database ) {
			$rows = $this->wpdb->get_results( $query, ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Callers pass statements built with $wpdb->prepare() or trusted table names only.

			if ( '' !== $this->wpdb->last_error || ! is_array( $rows ) ) {
				throw new RuntimeException( 'A database validation query failed.' );
			}

			return $rows;
		}

		$result = $this->database->query( $query, MYSQLI_STORE_RESULT );

		if ( false === $result ) {
			throw new RuntimeException( 'A direct database validation query failed.' );
		}

		if ( true === $result ) {
			return array();
		}

		$rows = $result->fetch_all( MYSQLI_ASSOC );

		$result->free();
		return $rows;
	}

	/**
	 * Returns the first column of the first row of a read-only query.
	 *
	 * @param string $query Read-only SELECT or SHOW statement, already prepared.
	 * @return mixed The value, or null when the query returns no rows.
	 */
	private function direct_value( string $query ): mixed {
		$rows = $this->direct_rows( $query );

		if ( ! isset( $rows[0] ) ) {
			return null;
		}

		$values = array_values( $rows[0] );
		return $values[0] ?? null;
	}

	/**
	 * Returns the first column of every row of a read-only query.
	 *
	 * @param string $query Read-only SELECT or SHOW statement, already prepared.
	 * @return array<int,mixed>
	 */
	private function direct_column( string $query ): array {
		return array_map(
			static function ( array $row ): mixed {
				$values = array_values( $row );
				return $values[0] ?? null;
			},
			$this->direct_rows( $query )
		);
	}

	/**
	 * Unserializes a stored value without creating objects.
	 *
	 * @param string $value Raw stored value.
	 * @return mixed The unserialized value, the original string when it is not serialized, or null when it is too large.
	 */
	private function safe_unserialize( string $value ): mixed {
		if ( strlen( $value ) > 4194304 ) {
			return null;
		}

		if ( ! is_serialized( $value ) ) {
			return $value;
		}

		// Malformed stored values are expected scan input and are reported by the callers, so the notice is silenced.
		return @unserialize( trim( $value ), array( 'allowed_classes' => false ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize -- Object creation is disabled.
	}

	/**
	 * Returns every users-table row, without password hashes, cached for the request.
	 *
	 * @return array<int, array<string,mixed>>
	 */
	private function database_users(): array {
		if ( null !== $this->database_users ) {
			return $this->database_users;
		}

		$this->database_users = $this->direct_rows(
			"SELECT ID, user_login, user_email, user_registered, user_status FROM {$this->wpdb->users} ORDER BY ID ASC"
		);

		return $this->database_users;
	}

	/**
	 * Users the current test is scoped to: site members on multisite, everyone otherwise.
	 *
	 * @return array<int, array<string,mixed>>
	 */
	private function scoped_users(): array {
		return array_values(
			array_filter(
				$this->database_users(),
				fn ( array $row ): bool => $this->in_scope( (int) $row['ID'] )
			)
		);
	}

	/**
	 * Whether a user belongs to the current test scope.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	private function in_scope( int $user_id ): bool {
		return null === $this->member_ids || isset( $this->member_ids[ $user_id ] );
	}

	/**
	 * Whether a user holds sensitive capabilities in the current scope.
	 *
	 * Matches WordPress core: super administrators hold every capability on every site,
	 * and everyone else holds only what a site's capability record grants.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	private function is_privileged( int $user_id ): bool {
		if ( isset( $this->super_admin_ids()[ $user_id ] ) ) {
			return true;
		}

		if ( 'network' === $this->scope && null === $this->member_ids ) {
			return isset( $this->network_access()['sensitive'][ $user_id ] );
		}

		return (bool) $this->database_user_access( $user_id )['sensitive'];
	}

	/**
	 * Resolves super administrators the way get_super_admins() does, without option filters.
	 *
	 * @return string[]
	 */
	private function super_admin_logins(): array {
		global $super_admins;

		if ( ! is_multisite() ) {
			return array();
		}

		if ( isset( $super_admins ) ) {
			return is_array( $super_admins ) ? array_values( array_filter( $super_admins, 'is_string' ) ) : array();
		}

		$raw    = $this->database_network_option_value( 'site_admins' );
		$logins = '' === $raw ? array( 'admin' ) : $this->safe_unserialize( $raw );

		return is_array( $logins ) ? array_values( array_filter( $logins, 'is_string' ) ) : array();
	}

	/**
	 * Maps super administrator logins to user IDs.
	 *
	 * Matches logins exactly, as is_super_admin() does.
	 *
	 * @return array<int,bool>
	 */
	private function super_admin_ids(): array {
		if ( null !== $this->super_admin_ids ) {
			return $this->super_admin_ids;
		}

		$logins                = array_fill_keys( $this->super_admin_logins(), true );
		$this->super_admin_ids = array();

		foreach ( $this->database_users() as $row ) {
			if ( isset( $logins[ (string) $row['user_login'] ] ) ) {
				$this->super_admin_ids[ (int) $row['ID'] ] = true;
			}
		}

		return $this->super_admin_ids;
	}

	/**
	 * Lists the current network's sites from the raw blogs table.
	 *
	 * @return array<int,array{blog_id:int,label:string}>
	 */
	public function network_sites(): array {
		if ( null !== $this->network_sites ) {
			return $this->network_sites;
		}

		$this->network_sites = array();

		if ( ! is_multisite() ) {
			return $this->network_sites;
		}

		$rows = $this->direct_rows(
			$this->wpdb->prepare(
				'SELECT blog_id, domain, path FROM %i WHERE site_id = %d ORDER BY blog_id ASC',
				$this->wpdb->blogs,
				(int) $this->wpdb->siteid
			)
		);

		foreach ( $rows as $row ) {
			$this->network_sites[] = array(
				'blog_id' => (int) $row['blog_id'],
				'label'   => untrailingslashit( (string) $row['domain'] . (string) $row['path'] ),
			);
		}

		return $this->network_sites;
	}

	/**
	 * Returns the domain and path label for a network site.
	 *
	 * @param int $site_id Site ID.
	 * @return string
	 */
	private function label_for_site( int $site_id ): string {
		foreach ( $this->network_sites() as $site ) {
			if ( $site['blog_id'] === $site_id ) {
				return $site['label'];
			}
		}

		return 'Site ' . $site_id;
	}

	/**
	 * Builds membership and sensitive access across every network site from raw records.
	 *
	 * @return array{members:array<int,bool>,sensitive:array<int,bool>}
	 */
	private function network_access(): array {
		if ( null !== $this->network_access ) {
			return $this->network_access;
		}

		$members       = array();
		$sensitive_ids = array();
		$sensitive     = $this->all_sensitive_capabilities();

		foreach ( $this->network_sites() as $site ) {
			$prefix   = $this->wpdb->get_blog_prefix( $site['blog_id'] );
			$roles    = $this->safe_unserialize( $this->database_option_value( $prefix . 'user_roles', $prefix . 'options' ) );
			$roles    = is_array( $roles ) ? $roles : array();
			$resolved = array();
			$rows     = $this->direct_rows(
				$this->wpdb->prepare(
					'SELECT umeta_id, user_id, meta_value FROM %i WHERE meta_key = %s ORDER BY user_id, umeta_id',
					$this->wpdb->usermeta,
					$prefix . 'capabilities'
				)
			);

			foreach ( $rows as $row ) {
				$user_id             = (int) $row['user_id'];
				$members[ $user_id ] = true;

				// WP_User reads only the first capability row by umeta_id.
				if ( isset( $resolved[ $user_id ] ) ) {
					continue;
				}

				$resolved[ $user_id ] = true;
				$capabilities         = $this->safe_unserialize( (string) $row['meta_value'] );

				if ( ! is_array( $capabilities ) ) {
					continue;
				}

				if ( array_intersect( $this->resolve_capabilities( $capabilities, $roles )['effective'], $sensitive ) ) {
					$sensitive_ids[ $user_id ] = true;
				}
			}
		}

		$this->network_access = array(
			'members'   => $members,
			'sensitive' => $sensitive_ids,
		);

		return $this->network_access;
	}

	/**
	 * Counts usermeta rows without a matching users-table record.
	 *
	 * @return int
	 */
	private function orphan_meta_rows(): int {
		return (int) $this->direct_value(
			"SELECT COUNT(um.umeta_id) FROM {$this->wpdb->usermeta} um LEFT JOIN {$this->wpdb->users} u ON u.ID = um.user_id WHERE u.ID IS NULL"
		);
	}

	/**
	 * Whether a password hash uses a format WordPress produces or accepts.
	 *
	 * @param string $hash Stored password hash.
	 * @return bool
	 */
	private function is_recognized_password_hash( string $hash ): bool {
		return str_starts_with( $hash, '$P$' )
			|| str_starts_with( $hash, '$H$' )
			|| str_starts_with( $hash, '$wp$2y$' )
			|| str_starts_with( $hash, '$2a$' )
			|| str_starts_with( $hash, '$2b$' )
			|| str_starts_with( $hash, '$2y$' )
			|| str_starts_with( $hash, '$argon2i$' )
			|| str_starts_with( $hash, '$argon2id$' );
	}

	/**
	 * Returns every users-table row keyed by user ID.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private function database_users_by_id(): array {
		$users = array();

		foreach ( $this->database_users() as $row ) {
			$users[ (int) $row['ID'] ] = $row;
		}

		return $users;
	}

	/**
	 * Finds a user row by ID.
	 *
	 * @param array<int, array<string,mixed>> $rows    Users-table rows.
	 * @param int                             $user_id User ID.
	 * @return array<string,mixed>
	 */
	private function find_database_user( array $rows, int $user_id ): array {
		foreach ( $rows as $row ) {
			if ( (int) $row['ID'] === $user_id ) {
				return $row;
			}
		}

		return array();
	}

	/**
	 * Builds access from raw capability metadata and the raw role option.
	 * No WordPress user, role, option, or metadata filter can change this result.
	 * Only the first capability row by umeta_id is used, as WP_User reads it; duplicate rows are reported by the metadata test.
	 *
	 * @param int $user_id User ID.
	 * @return array{roles:string[],direct:string[],effective:string[],sensitive:string[],numeric:string[],undefined:string[]}
	 */
	private function database_user_access( int $user_id ): array {
		$rows         = $this->database_capability_rows_by_user()[ $user_id ] ?? array();
		$capabilities = isset( $rows[0] ) ? $this->safe_unserialize( (string) $rows[0]['meta_value'] ) : null;
		$resolved     = $this->resolve_capabilities( is_array( $capabilities ) ? $capabilities : array(), $this->role_definitions );
		$roles        = $resolved['roles'];
		$direct       = $resolved['direct'];
		$effective    = $resolved['effective'];
		$numeric      = $resolved['numeric'];
		$sensitive    = array_values( array_intersect( $effective, $this->all_sensitive_capabilities() ) );
		sort( $roles );
		sort( $direct );
		sort( $effective );
		sort( $sensitive );
		sort( $numeric );

		$role_capabilities = $this->role_capabilities();
		$undefined         = array_values( array_filter( $direct, static fn ( string $capability ): bool => ! isset( $role_capabilities[ $capability ] ) ) );

		return compact( 'roles', 'direct', 'effective', 'sensitive', 'numeric', 'undefined' );
	}

	/**
	 * Resolves roles and granted capabilities from one raw capability record the way WP_User::get_role_caps() does.
	 * Every key that names a role grants that role whatever its value, role capabilities merge in record order,
	 * and direct entries, including false ones, override them.
	 *
	 * @param array<int|string,mixed> $capabilities Unserialized capability record.
	 * @param array<string,mixed>     $roles        Raw role definitions.
	 * @return array{roles:string[],direct:string[],effective:string[],numeric:string[]}
	 */
	private function resolve_capabilities( array $capabilities, array $roles ): array {
		$role_slugs = array();
		$direct     = array();
		$numeric    = array();
		$allcaps    = array();

		foreach ( array_keys( $capabilities ) as $capability ) {
			$capability = (string) $capability;

			if ( ! ctype_digit( $capability ) && array_key_exists( $capability, $roles ) ) {
				$role_slugs[] = $capability;
			}
		}

		foreach ( $role_slugs as $role_slug ) {
			$role_data = $roles[ $role_slug ];

			foreach ( is_array( $role_data ) ? (array) ( $role_data['capabilities'] ?? array() ) : array() as $capability => $granted ) {
				$allcaps[ (string) $capability ] = $granted;
			}
		}

		foreach ( $capabilities as $capability => $granted ) {
			$capability = (string) $capability;

			if ( ctype_digit( $capability ) ) {
				if ( $granted ) {
					$numeric[] = $capability;
				}
				continue;
			}

			if ( in_array( $capability, $role_slugs, true ) ) {
				continue;
			}

			$allcaps[ $capability ] = $granted;

			if ( $granted ) {
				$direct[] = $capability;
			}
		}

		return array(
			'roles'     => $role_slugs,
			'direct'    => $direct,
			'effective' => array_map( 'strval', array_keys( array_filter( $allcaps ) ) ),
			'numeric'   => $numeric,
		);
	}

	/**
	 * Compares runtime capability checks with access derived from raw database records.
	 * Super administrators are skipped because core grants them every capability at runtime.
	 *
	 * @param int      $user_id   User ID.
	 * @param string[] $effective Capabilities derived from raw database records.
	 * @return array{granted:string[],denied:string[]}
	 */
	private function runtime_access_differences( int $user_id, array $effective ): array {
		$differences = array(
			'granted' => array(),
			'denied'  => array(),
		);

		if ( isset( $this->super_admin_ids()[ $user_id ] ) ) {
			return $differences;
		}

		$user = new WP_User( $user_id );

		if ( ! $user->exists() ) {
			return $differences;
		}

		$stored = array_fill_keys( $effective, true );

		foreach ( $this->all_sensitive_capabilities() as $capability ) {
			$allowed = $user->has_cap( $capability );

			if ( $allowed && ! isset( $stored[ $capability ] ) ) {
				$differences['granted'][] = $capability;
			} elseif ( ! $allowed && isset( $stored[ $capability ] ) && ! $this->core_denies_capability( $capability, $user_id ) ) {
				$differences['denied'][] = $capability;
			}
		}

		return $differences;
	}

	/**
	 * Whether core's map_meta_cap() denies a capability to this user by design.
	 * Mirrors the file-modification, unfiltered-HTML, and multisite restrictions so they are not reported as tampering.
	 *
	 * @param string $capability Capability name.
	 * @param int    $user_id    User ID.
	 * @return bool
	 */
	private function core_denies_capability( string $capability, int $user_id ): bool {
		$network_restricted = is_multisite() && ! is_super_admin( $user_id );

		if ( in_array( $capability, array( 'edit_files', 'edit_plugins', 'edit_themes' ), true ) ) {
			return ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) || ! wp_is_file_mod_allowed( 'capability_edit_themes' ) || $network_restricted;
		}

		if ( in_array( $capability, array( 'delete_plugins', 'delete_themes', 'install_plugins', 'install_themes', 'update_core', 'update_plugins', 'update_themes' ), true ) ) {
			return ! wp_is_file_mod_allowed( 'capability_update_core' ) || $network_restricted;
		}

		if ( 'unfiltered_html' === $capability ) {
			return ( defined( 'DISALLOW_UNFILTERED_HTML' ) && DISALLOW_UNFILTERED_HTML ) || $network_restricted;
		}

		if ( 'unfiltered_upload' === $capability ) {
			return ! ( defined( 'ALLOW_UNFILTERED_UPLOADS' ) && ALLOW_UNFILTERED_UPLOADS ) || $network_restricted;
		}

		if ( 'delete_users' === $capability ) {
			return $network_restricted;
		}

		if ( 'create_users' === $capability ) {
			return $network_restricted && ! get_site_option( 'add_new_users' );
		}

		if ( 'edit_users' === $capability ) {
			return is_multisite() && ! user_can( $user_id, 'manage_network_users' );
		}

		if ( 'activate_plugins' === $capability ) {
			$menu_items = (array) get_site_option( 'menu_items', array() );

			return is_multisite() && empty( $menu_items['plugins'] ) && ! user_can( $user_id, 'manage_network_plugins' );
		}

		return false;
	}

	/**
	 * Builds the finding for role definitions set by the $wp_user_roles global.
	 * WP_Roles uses the global before the stored role option whenever it is non-empty.
	 *
	 * @return array<string,mixed>|null The finding, or null when the global is empty.
	 */
	private function user_roles_global_finding(): ?array {
		global $wp_user_roles;

		if ( empty( $wp_user_roles ) ) {
			return null;
		}

		return $this->finding(
			'high',
			'Role definitions are defined in code',
			'The $wp_user_roles global is set, so WordPress ignores the stored user_roles option' . ( is_multisite() ? ' on every site in the network' : '' ) . '. Roles defined in code: ' . ( is_array( $wp_user_roles ) ? $this->bounded_list( array_map( 'strval', array_keys( $wp_user_roles ) ) ) : 'none readable' ) . '.',
			'Locate where the global is defined, usually wp-config.php, compare it with the stored role option, and remove the override unless it is an approved configuration.'
		);
	}

	/**
	 * Compares the role definitions WordPress enforces at runtime with the raw role option.
	 *
	 * @return array<int,array<string,mixed>> One finding for every role that differs.
	 */
	private function runtime_role_findings(): array {
		$findings  = array();
		$sensitive = $this->all_sensitive_capabilities();
		$runtime   = wp_roles()->roles;
		$slugs     = array_map( 'strval', array_unique( array_merge( array_keys( $this->role_definitions ), array_keys( $runtime ) ) ) );

		sort( $slugs );

		foreach ( $slugs as $role_slug ) {
			if ( ! isset( $runtime[ $role_slug ] ) ) {
				$findings[] = $this->finding(
					'medium',
					'Stored role is not enforced at runtime',
					'Role "' . $role_slug . '" exists in the raw role option, but WordPress does not load it.',
					'Inspect the $wp_user_roles global and role-option filters for definitions that replace the stored roles.'
				);
				continue;
			}

			$is_stored = isset( $this->role_definitions[ $role_slug ] );
			$stored    = $this->granted_role_capabilities( $this->role_definitions[ $role_slug ] ?? null );
			$enforced  = $this->granted_role_capabilities( $runtime[ $role_slug ] );
			$gained    = array_values( array_diff( $enforced, $stored ) );
			$lost      = array_values( array_diff( $stored, $enforced ) );

			if ( $is_stored && ! $gained && ! $lost ) {
				continue;
			}

			if ( 'administrator' !== $role_slug && array_intersect( self::CRITICAL_CAPABILITIES, $gained ) ) {
				$severity = 'critical';
			} elseif ( array_intersect( $gained, $sensitive ) ) {
				$severity = 'high';
			} else {
				$severity = 'medium';
			}

			$findings[] = $this->finding(
				$severity,
				$is_stored ? 'Role definition differs at runtime' : 'Role exists only at runtime',
				'Role "' . $role_slug . '" ' . ( $is_stored ? 'differs from the raw role option at runtime.' : 'is enforced at runtime but absent from the raw role option.' ) . ( $gained ? ' Gained at runtime: ' . $this->bounded_list( $gained ) . '.' : '' ) . ( $lost ? ' Lost at runtime: ' . $this->bounded_list( $lost ) . '.' : '' ),
				'Inspect the $wp_user_roles global and active option and pre_option filters on the role option, and confirm every difference with the site owner.'
			);
		}

		return $findings;
	}

	/**
	 * Lists the capabilities a role definition grants.
	 *
	 * @param mixed $role_data Role definition with a capabilities array.
	 * @return string[]
	 */
	private function granted_role_capabilities( mixed $role_data ): array {
		if ( ! is_array( $role_data ) || ! isset( $role_data['capabilities'] ) || ! is_array( $role_data['capabilities'] ) ) {
			return array();
		}

		return array_map( 'strval', array_keys( array_filter( $role_data['capabilities'] ) ) );
	}

	/**
	 * Every capability granted by at least one role on the current site.
	 *
	 * @return array<string,bool>
	 */
	private function role_capabilities(): array {
		if ( null !== $this->role_capabilities ) {
			return $this->role_capabilities;
		}

		$this->role_capabilities = array();

		foreach ( $this->role_definitions as $role_data ) {
			foreach ( is_array( $role_data ) ? (array) ( $role_data['capabilities'] ?? array() ) : array() as $capability => $granted ) {
				if ( $granted ) {
					$this->role_capabilities[ (string) $capability ] = true;
				}
			}
		}

		return $this->role_capabilities;
	}

	/**
	 * Returns the current site's raw capability rows grouped by user ID.
	 *
	 * @return array<int,array<int,array<string,mixed>>>
	 */
	private function database_capability_rows_by_user(): array {
		if ( null !== $this->capability_rows_by_user ) {
			return $this->capability_rows_by_user;
		}

		$rows                          = $this->direct_rows(
			$this->wpdb->prepare(
				'SELECT umeta_id, user_id, meta_value FROM %i WHERE meta_key = %s ORDER BY user_id, umeta_id',
				$this->wpdb->usermeta,
				$this->wpdb->prefix . 'capabilities'
			)
		);
		$this->capability_rows_by_user = array();

		foreach ( $rows as $row ) {
			$this->capability_rows_by_user[ (int) $row['user_id'] ][] = $row;
		}

		return $this->capability_rows_by_user;
	}

	/**
	 * Returns the administrator-level and additional sensitive capabilities.
	 *
	 * @return string[]
	 */
	private function all_sensitive_capabilities(): array {
		return array_values( array_unique( array_merge( self::CRITICAL_CAPABILITIES, self::SENSITIVE_CAPABILITIES ) ) );
	}

	/**
	 * Counts unexpired session tokens.
	 *
	 * @param array<string,mixed> $tokens Unserialized session_tokens value.
	 * @return int
	 */
	private function active_token_count( array $tokens ): int {
		$now    = time();
		$active = 0;

		foreach ( $tokens as $token ) {
			if ( is_array( $token ) && isset( $token['expiration'] ) && (int) $token['expiration'] > $now ) {
				++$active;
			}
		}

		return $active;
	}

	/**
	 * Returns active session counts keyed by user ID.
	 *
	 * @return array<int,int>
	 */
	private function database_session_counts(): array {
		return $this->database_serialized_meta_counts( 'session_tokens', true );
	}

	/**
	 * Returns application-password counts keyed by user ID.
	 *
	 * @return array<int,int>
	 */
	private function database_application_password_counts(): array {
		return $this->database_serialized_meta_counts( '_application_passwords', false );
	}

	/**
	 * Counts entries in a serialized usermeta value for every user.
	 *
	 * @param string $meta_key        Usermeta key.
	 * @param bool   $active_sessions Count only unexpired session tokens.
	 * @return array<int,int>
	 */
	private function database_serialized_meta_counts( string $meta_key, bool $active_sessions ): array {
		$rows   = $this->direct_rows(
			$this->wpdb->prepare(
				'SELECT user_id, meta_value FROM %i WHERE meta_key = %s',
				$this->wpdb->usermeta,
				$meta_key
			)
		);
		$counts = array();

		foreach ( $rows as $row ) {
			$user_id            = (int) $row['user_id'];
			$values             = $this->safe_unserialize( (string) $row['meta_value'] );
			$count              = is_array( $values ) ? ( $active_sessions ? $this->active_token_count( $values ) : count( $values ) ) : 0;
			$counts[ $user_id ] = ( $counts[ $user_id ] ?? 0 ) + $count;
		}

		return $counts;
	}

	/**
	 * Reads a raw option value without option filters.
	 *
	 * @param string $option_name Option name.
	 * @param string $table       Options table; defaults to the current site's.
	 * @return string The raw value, or an empty string when it is missing.
	 */
	private function database_option_value( string $option_name, string $table = '' ): string {
		$table = '' !== $table ? $table : $this->wpdb->options;
		$value = $this->direct_value(
			$this->wpdb->prepare(
				'SELECT option_value FROM %i WHERE option_name = %s ORDER BY option_id ASC LIMIT 1',
				$table,
				$option_name
			)
		);

		return is_string( $value ) ? $value : '';
	}

	/**
	 * Reads a raw network option value without option filters.
	 *
	 * @param string $option_name Network option name.
	 * @return string The raw value, or an empty string when it is missing or not multisite.
	 */
	private function database_network_option_value( string $option_name ): string {
		if ( ! is_multisite() ) {
			return '';
		}

		$value = $this->direct_value(
			$this->wpdb->prepare(
				'SELECT meta_value FROM %i WHERE site_id = %d AND meta_key = %s ORDER BY meta_id ASC LIMIT 1',
				$this->wpdb->sitemeta,
				(int) $this->wpdb->siteid,
				$option_name
			)
		);

		return is_string( $value ) ? $value : '';
	}

	/**
	 * Returns authored post counts keyed by user ID.
	 *
	 * @return array<int,int>
	 */
	private function authored_content_counts(): array {
		$rows   = $this->direct_rows(
			"SELECT post_author, COUNT(ID) AS record_count FROM {$this->wpdb->posts} WHERE post_author > 0 GROUP BY post_author"
		);
		$counts = array();

		foreach ( $rows as $row ) {
			$counts[ (int) $row['post_author'] ] = (int) $row['record_count'];
		}

		return $counts;
	}

	/**
	 * Returns user IDs with a WooCommerce customer lookup record.
	 *
	 * @return array<int,bool>
	 */
	private function woocommerce_customer_ids(): array {
		$table  = $this->wpdb->prefix . 'wc_customer_lookup';
		$exists = $this->direct_value( $this->wpdb->prepare( 'SHOW TABLES LIKE %s', $this->wpdb->esc_like( $table ) ) );

		if ( $table !== $exists ) {
			return array();
		}

		$ids = $this->direct_column( "SELECT DISTINCT user_id FROM {$table} WHERE user_id IS NOT NULL AND user_id > 0" );
		return array_fill_keys( array_map( 'intval', $ids ), true );
	}

	/**
	 * Groups users registered within 15 minutes of each other into clusters of three or more.
	 *
	 * @param array<int, array<string,mixed>> $rows Users-table rows.
	 * @return array<int, array<int, array<string,mixed>>>
	 */
	private function registration_clusters( array $rows ): array {
		$clusters           = array();
		$current            = array();
		$cluster_start_time = null;

		usort(
			$rows,
			static fn ( array $left, array $right ): int => strcmp( (string) $left['user_registered'], (string) $right['user_registered'] )
		);

		foreach ( $rows as $row ) {
			if ( str_starts_with( (string) $row['user_registered'], '0000-00-00' ) ) {
				continue;
			}
			$timestamp = strtotime( (string) $row['user_registered'] . ' UTC' );

			if ( false === $timestamp ) {
				continue;
			}

			if ( null === $cluster_start_time || $timestamp - $cluster_start_time <= 15 * MINUTE_IN_SECONDS ) {
				$current[] = $row;
			} else {
				if ( count( $current ) >= 3 ) {
					$clusters[] = $current;
				}
				$current            = array( $row );
				$cluster_start_time = $timestamp;
			}

			if ( null === $cluster_start_time ) {
				$cluster_start_time = $timestamp;
			}
		}

		if ( count( $current ) >= 3 ) {
			$clusters[] = $current;
		}

		return array_slice( $clusters, 0, 20 );
	}
	/**
	 * Lists the code paths the scan covers in this scope and records each root's kind.
	 *
	 * Every scope covers its active plugins and themes and its own uploads folder. Single-site and network
	 * scans also cover inactive plugins and themes, network-active plugins, must-use plugins, PHP files in
	 * the wp-content root, wp-config.php, and PHP prepend or append files.
	 *
	 * @return string[]
	 */
	private function active_code_roots(): array {
		$roots                    = array();
		$this->root_findings      = array();
		$this->excluded_paths     = array();
		$network_roots            = ! is_multisite() || 'network' === $this->scope;
		$option_tables            = array( $this->wpdb->options );
		$this->verified_own_files = $this->verify_own_files();

		if ( 'network' === $this->scope ) {
			$option_tables = array_map(
				fn ( array $site ): string => $this->wpdb->get_blog_prefix( $site['blog_id'] ) . 'options',
				$this->network_sites()
			);
		}

		foreach ( $option_tables as $option_table ) {
			$active_plugins = $this->safe_unserialize( $this->database_option_value( 'active_plugins', $option_table ) );

			foreach ( is_array( $active_plugins ) ? $active_plugins : array() as $plugin_file ) {
				$root = $this->plugin_root( (string) $plugin_file );

				if ( null === $root ) {
					continue;
				}

				$roots[ $root ] = 'active';
			}

			$stylesheet = basename( $this->database_option_value( 'stylesheet', $option_table ) );
			$template   = basename( $this->database_option_value( 'template', $option_table ) );

			if ( '' !== $stylesheet ) {
				$roots[ $this->theme_root_path( $this->database_option_value( 'stylesheet_root', $option_table ) ) . '/' . $stylesheet ] = 'active';
			}

			if ( '' !== $template ) {
				$roots[ $this->theme_root_path( $this->database_option_value( 'template_root', $option_table ) ) . '/' . $template ] = 'active';
			}
		}

		if ( $network_roots && is_multisite() ) {
			$sitewide_plugins_value = $this->direct_value(
				$this->wpdb->prepare(
					'SELECT meta_value FROM %i WHERE site_id = %d AND meta_key = %s ORDER BY meta_id ASC LIMIT 1',
					$this->wpdb->sitemeta,
					(int) $this->wpdb->siteid,
					'active_sitewide_plugins'
				)
			);
			$sitewide_plugins       = $this->safe_unserialize( is_string( $sitewide_plugins_value ) ? $sitewide_plugins_value : '' );

			foreach ( array_keys( is_array( $sitewide_plugins ) ? $sitewide_plugins : array() ) as $plugin_file ) {
				$root = $this->plugin_root( (string) $plugin_file );

				if ( null !== $root ) {
					$roots[ $root ] = 'active';
				}
			}
		}

		if ( $network_roots && is_dir( WPMU_PLUGIN_DIR ) ) {
			$roots[ WPMU_PLUGIN_DIR ] = 'active';
		}

		if ( $network_roots ) {
			foreach ( $this->directory_entries( WP_PLUGIN_DIR ) as $plugin_entry ) {
				if ( is_link( $plugin_entry ) && ! isset( $roots[ $plugin_entry ] ) ) {
					$this->root_findings[] = $this->symlink_finding( $plugin_entry, 'inactive' );
					continue;
				}

				if ( is_dir( $plugin_entry ) || in_array( strtolower( pathinfo( $plugin_entry, PATHINFO_EXTENSION ) ), self::PHP_EXTENSIONS, true ) ) {
					$roots[ $plugin_entry ] ??= 'inactive';
				}
			}

			foreach ( $this->theme_directories() as $theme_directory ) {
				foreach ( $this->directory_entries( $theme_directory ) as $theme_entry ) {
					if ( is_link( $theme_entry ) && ! isset( $roots[ $theme_entry ] ) ) {
						$this->root_findings[] = $this->symlink_finding( $theme_entry, 'inactive' );
						continue;
					}

					if ( is_dir( $theme_entry ) ) {
						$roots[ $theme_entry ] ??= 'inactive';
					}
				}
			}

			foreach ( $this->directory_entries( WP_CONTENT_DIR ) as $content_entry ) {
				if ( is_link( $content_entry ) && in_array( strtolower( pathinfo( $content_entry, PATHINFO_EXTENSION ) ), self::PHP_EXTENSIONS, true ) ) {
					$this->root_findings[] = $this->symlink_finding( $content_entry, 'content' );
					continue;
				}

				if ( is_file( $content_entry ) && in_array( strtolower( pathinfo( $content_entry, PATHINFO_EXTENSION ) ), self::PHP_EXTENSIONS, true ) ) {
					$roots[ $content_entry ] = in_array( basename( $content_entry ), self::KNOWN_CONTENT_FILES, true ) ? 'active' : 'content';
				}
			}

			// Matches core's wp-config.php lookup in wp-load.php.
			if ( file_exists( ABSPATH . 'wp-config.php' ) ) {
				$roots[ ABSPATH . 'wp-config.php' ] = 'config';
			} elseif ( file_exists( dirname( ABSPATH ) . '/wp-config.php' ) && ! file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ) {
				$roots[ dirname( ABSPATH ) . '/wp-config.php' ] = 'config';
			}

			$user_ini_name = (string) ini_get( 'user_ini.filename' );

			foreach ( array_unique( array( ABSPATH, trailingslashit( WP_CONTENT_DIR ) ) ) as $config_directory ) {
				foreach ( array_filter( array( '.htaccess', $user_ini_name ) ) as $config_name ) {
					if ( is_file( $config_directory . $config_name ) ) {
						$roots[ $config_directory . $config_name ] = 'config';
					}
				}
			}

			foreach ( array( 'auto_prepend_file', 'auto_append_file' ) as $directive ) {
				$directive_file = (string) ini_get( $directive );

				if ( '' === $directive_file ) {
					continue;
				}

				$readable              = is_file( $directive_file ) && is_readable( $directive_file );
				$this->root_findings[] = $this->finding(
					'high',
					'PHP runs a file on every request',
					'The ' . $directive . ' setting is ' . $directive_file . '.' . ( $readable ? ' The file was added to the code scan.' : ' The file is not readable and was not scanned.' ),
					'Confirm the file belongs to an approved tool, such as a web application firewall, and locate where the setting is defined in php.ini, .user.ini, or .htaccess.'
				);

				if ( $readable ) {
					$roots[ $directive_file ] ??= 'prepend';
				}
			}
		}

		$uploads           = wp_upload_dir( null, false );
		$uploads_directory = ! empty( $uploads['basedir'] ) ? untrailingslashit( (string) $uploads['basedir'] ) : '';

		if ( '' !== $uploads_directory && is_dir( $uploads_directory ) ) {
			$roots[ $uploads_directory ] = 'uploads';

			// The main site's uploads folder holds every subsite's uploads, which belong to their own site scans.
			if ( 'site' === $this->scope && is_multisite() && is_main_site() ) {
				$this->excluded_paths[] = str_replace( '\\', '/', $uploads_directory ) . '/sites/';
			}
		}

		// Sites upgraded from before WordPress 3.5 can keep uploads in the legacy blogs.dir folder.
		if ( is_multisite() ) {
			$blogs_directory = WP_CONTENT_DIR . '/blogs.dir' . ( 'network' === $this->scope ? '' : '/' . get_current_blog_id() );

			if ( is_dir( $blogs_directory ) ) {
				if ( '' !== $uploads_directory && str_starts_with( str_replace( '\\', '/', $uploads_directory ) . '/', str_replace( '\\', '/', $blogs_directory ) . '/' ) ) {
					unset( $roots[ $uploads_directory ] );
				}

				$roots[ $blogs_directory ] = 'uploads';
			}
		}

		$this->root_kinds = $roots;

		return array_values( array_filter( array_keys( $roots ), 'file_exists' ) );
	}

	/**
	 * Lists the entries directly inside a directory, sorted, without dot entries.
	 * Symbolic links are included so callers can report them.
	 *
	 * @param string $directory Directory path.
	 * @return string[] Absolute entry paths.
	 */
	private function directory_entries( string $directory ): array {
		$entries = is_dir( $directory ) ? scandir( $directory ) : false;
		$paths   = array();

		foreach ( false === $entries ? array() : $entries as $entry ) {
			$path = $directory . '/' . $entry;

			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}

			$paths[] = $path;
		}

		return $paths;
	}

	/**
	 * Builds the finding for a symbolic link the code scan does not follow.
	 *
	 * @param string $path      Link path.
	 * @param string $root_kind Kind of the root the link was found in.
	 * @return array<string,mixed>
	 */
	private function symlink_finding( string $path, string $root_kind ): array {
		$target = realpath( $path );

		return $this->finding(
			'uploads' === $root_kind ? 'high' : 'medium',
			'Symbolic link was not scanned',
			'Link: ' . $this->relative_path( $path ) . '. ' . ( false === $target ? 'The link target does not exist or is not readable.' : 'It points to ' . $target . '.' ) . ' Code behind symbolic links is not scanned.',
			'Confirm the link target is an approved deployment path and scan it separately.'
		);
	}

	/**
	 * Resolves a raw stylesheet_root or template_root option to a theme directory the way get_theme_root() does.
	 * Registered theme directories are stored as absolute paths; anything else is relative to the content directory.
	 *
	 * @param string $raw_root Raw theme root option value.
	 * @return string Theme directory path, without a trailing slash.
	 */
	private function theme_root_path( string $raw_root ): string {
		global $wp_theme_directories;

		if ( '' === $raw_root ) {
			return WP_CONTENT_DIR . '/themes';
		}

		return untrailingslashit( in_array( $raw_root, (array) $wp_theme_directories, true ) ? $raw_root : WP_CONTENT_DIR . $raw_root );
	}

	/**
	 * Lists the default and every registered theme directory.
	 *
	 * @return string[] Theme directory paths, without trailing slashes.
	 */
	private function theme_directories(): array {
		global $wp_theme_directories;

		return array_values( array_unique( array_map( 'untrailingslashit', array_merge( array( WP_CONTENT_DIR . '/themes' ), array_map( 'strval', (array) $wp_theme_directories ) ) ) ) );
	}

	/**
	 * Resolves an active plugin entry to a scan root inside the plugins directory.
	 * Traversal entries and roots that resolve outside the directory are reported and skipped.
	 *
	 * @param string $plugin_file Active plugin entry, relative to the plugins directory.
	 * @return string|null The scan root, or null when the entry is skipped.
	 */
	private function plugin_root( string $plugin_file ): ?string {
		$normalized = str_replace( '\\', '/', $plugin_file );

		if ( '' === $normalized || str_starts_with( $normalized, '/' ) || preg_match( '#^[a-z]:#i', $normalized ) || preg_match( '#(?:^|/)\.\.(?:/|$)#', $normalized ) ) {
			$this->root_findings[] = $this->finding(
				'high',
				'Active plugin entry points outside the plugins directory',
				'The active plugin entry "' . $plugin_file . '" contains an absolute path or a parent-directory segment and was not scanned.',
				'Preserve the active plugin option, determine how the entry was written, and inspect the referenced file offline.'
			);
			return null;
		}

		$plugin_path       = WP_PLUGIN_DIR . '/' . $normalized;
		$plugin_directory  = dirname( $plugin_path );
		$root              = WP_PLUGIN_DIR === $plugin_directory ? $plugin_path : $plugin_directory;
		$resolved          = realpath( $root );
		$plugins_directory = realpath( WP_PLUGIN_DIR );

		if ( false === $resolved ) {
			return null;
		}

		if ( false === $plugins_directory || ! str_starts_with( str_replace( '\\', '/', $resolved ) . '/', trailingslashit( str_replace( '\\', '/', $plugins_directory ) ) ) ) {
			$this->root_findings[] = $this->finding(
				'medium',
				'Active plugin resolves outside the plugins directory',
				'Plugin root ' . $this->relative_path( $root ) . ' resolves to ' . $resolved . ' and was not scanned.',
				'Confirm the link target is an approved deployment path and scan it separately.'
			);
			return null;
		}

		return $root;
	}

	/**
	 * Detects CSS or script that hides rows on the Users screen.
	 *
	 * @param string $contents  File contents.
	 * @param string $extension Lowercase file extension.
	 * @return array<string,string>
	 */
	private function users_screen_hiding_patterns( string $contents, string $extension ): array {
		$css_hides_user_row    = preg_match(
			'/(?:#user-\d+|body\.users-php[^{}]*(?:#the-list|\.wp-list-table|tr)|(?:#the-list|table\.users|\.wp-list-table\.users)[^{}]*(?:tr|tbody))[^{}]*\{[^{}]*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\D|$)|max-height\s*:\s*0|height\s*:\s*0)/i',
			$contents
		);
		$script_hides_user_row = preg_match(
			'/(?:(?:querySelector(?:All)?|jQuery|\$)\s*\(\s*[\'\"][^\'\"]*(?:#user-\d+|#the-list[^\'\"]*tr|table\.users[^\'\"]*tr|\.wp-list-table\.users[^\'\"]*(?:tr|tbody))[^\'\"]*[\'\"]\s*\)|getElementById\s*\(\s*[\'\"]user-\d+[\'\"]\s*\)).{0,500}?(?:\.hide\s*\(|\.remove\s*\(|removeChild\s*\(|\.hidden\s*=|style\.display\s*=|setAttribute\s*\(\s*[\'\"](?:hidden|style)[\'\"])/is',
			$contents
		);

		$users_screen_context  = preg_match( '/users\.php|users-php|column-username|table\.users|wp-list-table\.users/i', $contents );
		$script_hides_by_login = $users_screen_context && preg_match(
			'/(?::contains\s*\(|\.column-username|\.(?:closest|parents?)\s*\(\s*[\'\"]tr[\'\"]\s*\)).{0,500}?(?:\.hide\s*\(|\.remove\s*\(|\.detach\s*\(|\.fadeOut\s*\(|removeChild\s*\(|\.hidden\s*=|style\.display\s*=|\.css\s*\(\s*[\'\"]display[\'\"]|setAttribute\s*\(\s*[\'\"](?:hidden|style)[\'\"])/is',
			$contents
		);
		$script_rewrites_count = preg_match(
			'/\.subsubsub.{0,300}?\.count.{0,300}?(?:\.(?:text|html)\s*\(\s*[^)\s]|\.(?:textContent|innerText|innerHTML)\s*=)/is',
			$contents
		);

		if ( 'css' === $extension && $css_hides_user_row ) {
			return array( 'users_screen_css_hide' => 'CSS may hide user rows on the Users screen' );
		}

		$patterns = array();

		if ( 'js' === $extension || in_array( $extension, self::PHP_EXTENSIONS, true ) ) {
			if ( $script_hides_user_row || $css_hides_user_row || $script_hides_by_login ) {
				$patterns['users_screen_script_hide'] = 'Code may hide or remove user rows on the Users screen';
			}

			if ( $script_rewrites_count ) {
				$patterns['users_screen_count_rewrite'] = 'Code may rewrite role counts on the Users screen';
			}
		}

		return $patterns;
	}

	/**
	 * Extracts user IDs targeted by user-row selectors or by login text in :contains() selectors.
	 *
	 * @param string $contents File contents.
	 * @return int[]
	 */
	private function users_screen_targeted_user_ids( string $contents ): array {
		preg_match_all( '/(?:#|[\'\"])user-(\d+)(?:\b|[\'\"])/i', $contents, $matches );
		preg_match_all( '/:contains\s*\(\s*([\'\"]?)([^\'\")]+)\1\s*\)/i', $contents, $login_matches );

		$user_ids = array_map( 'intval', $matches[1] ?? array() );
		$logins   = array_fill_keys( array_map( 'trim', $login_matches[2] ?? array() ), true );

		foreach ( $logins ? $this->database_users() : array() as $row ) {
			if ( isset( $logins[ (string) $row['user_login'] ] ) ) {
				$user_ids[] = (int) $row['ID'];
			}
		}

		return array_values( array_unique( $user_ids ) );
	}

	/**
	 * Whether code pins authentication to a literal user ID, a literal login, or a literal request value.
	 *
	 * @param string $contents File contents.
	 * @return bool
	 */
	private function has_hard_coded_identity( string $contents ): bool {
		return preg_match( '/\bwp_set_(?:auth_cookie|current_user)\s*\(\s*\d+\s*[,)]/', $contents ) === 1
			|| preg_match( '/\bget_user_by\s*\(\s*[\'"](?:login|id)[\'"]\s*,\s*(?:[\'"][^\'"]+[\'"]|\d+)\s*\)/i', $contents ) === 1
			|| preg_match( '/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*===?\s*[\'"][^\'"]+[\'"]|[\'"][^\'"]+[\'"]\s*===?\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/', $contents ) === 1;
	}

	/**
	 * Runs a callback with the Users screen simulated, so screen-conditional hiding code fires.
	 * The $pagenow and $current_screen globals and the REQUEST_URI, SCRIPT_NAME, and PHP_SELF server values change, and all are restored afterwards; no screen actions run.
	 *
	 * @param string   $screen_id Screen ID: 'users' or 'users-network'.
	 * @param callable $callback  Read-only evidence callback.
	 * @return mixed The callback result.
	 */
	private function in_users_screen( string $screen_id, callable $callback ): mixed {
		global $pagenow, $current_screen;

		$previous_pagenow = $pagenow;
		$previous_screen  = $current_screen;
		$previous_server  = array();
		$users_path       = (string) wp_parse_url( 'users-network' === $screen_id ? network_admin_url( 'users.php' ) : admin_url( 'users.php' ), PHP_URL_PATH );
		$pagenow          = 'users.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Simulates the Users screen and is restored below.
		$current_screen   = WP_Screen::get( $screen_id ); // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Simulates the Users screen and is restored below.

		foreach ( array( 'REQUEST_URI', 'SCRIPT_NAME', 'PHP_SELF' ) as $server_key ) {
			$previous_server[ $server_key ] = $_SERVER[ $server_key ] ?? null; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Saved verbatim and restored below.
			$_SERVER[ $server_key ]         = $users_path;
		}

		try {
			return $callback();
		} finally {
			$pagenow        = $previous_pagenow; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Restores the original value.
			$current_screen = $previous_screen; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Restores the original value.

			foreach ( $previous_server as $server_key => $server_value ) {
				if ( null === $server_value ) {
					unset( $_SERVER[ $server_key ] );
				} else {
					$_SERVER[ $server_key ] = $server_value;
				}
			}
		}
	}

	/**
	 * Runs the Users-screen query after the users_list_table_query_args filter, without paging.
	 *
	 * @param array<string,mixed> $args Default list-table query arguments.
	 * @return int[] User IDs the Users screen would list.
	 */
	private function users_screen_query_ids( array $args ): array {
		$args                = (array) apply_filters( 'users_list_table_query_args', $args ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Applies the core Users-screen filter to compare its result.
		$args['fields']      = 'ID';
		$args['number']      = -1;
		$args['offset']      = 0;
		$args['count_total'] = false;
		$query               = new WP_User_Query( $args );

		return array_map( 'intval', $query->get_results() );
	}

	/**
	 * Applies a Users-screen views filter to a baseline views array and lists removed or altered counts.
	 *
	 * @param string            $hook   Views filter name.
	 * @param array<string,int> $counts Baseline count for each view.
	 * @return string[] One description per changed view.
	 */
	private function filtered_view_changes( string $hook, array $counts ): array {
		$views   = array();
		$changes = array();

		foreach ( $counts as $view => $count ) {
			$views[ $view ] = sprintf(
				'<a href="%1$s">%2$s <span class="count">(%3$s)</span></a>',
				esc_url( add_query_arg( 'role', $view, 'users.php' ) ),
				esc_html( $view ),
				number_format_i18n( $count )
			);
		}

		$filtered = apply_filters( $hook, $views ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.DynamicHooknameFound -- Applies the core Users-screen views filter to compare its result.
		$filtered = is_array( $filtered ) ? $filtered : array();

		foreach ( $counts as $view => $count ) {
			if ( ! isset( $filtered[ $view ] ) ) {
				$changes[] = $view . ' removed';
				continue;
			}

			if ( ! preg_match( '/<span class="count">\(([^)<]*)\)/', (string) $filtered[ $view ], $match ) ) {
				$changes[] = $view . ' count removed';
				continue;
			}

			$shown = (int) preg_replace( '/\D/', '', $match[1] );

			if ( $shown !== $count ) {
				$changes[] = $view . ' shows ' . $shown . ' instead of ' . $count;
			}
		}

		return $changes;
	}

	/**
	 * Compares count_users() with counts built from the raw capability records the way core counts them.
	 *
	 * @param array<string,mixed> $counts     count_users() result.
	 * @param string[]            $role_slugs Roles WordPress counts.
	 * @return string[] One description per differing count.
	 */
	private function user_count_differences( array $counts, array $role_slugs ): array {
		$users    = $this->database_users_by_id();
		$expected = array_fill_keys( array_merge( array( 'total' ), $role_slugs, array( 'none' ) ), 0 );

		foreach ( $this->database_capability_rows_by_user() as $user_id => $rows ) {
			if ( ! isset( $users[ $user_id ] ) ) {
				continue;
			}

			foreach ( $rows as $row ) {
				$capabilities = $this->safe_unserialize( (string) $row['meta_value'] );
				++$expected['total'];

				if ( 'a:0:{}' === (string) $row['meta_value'] ) {
					++$expected['none'];
				}

				foreach ( is_array( $capabilities ) ? $role_slugs : array() as $role_slug ) {
					if ( array_key_exists( $role_slug, $capabilities ) ) {
						++$expected[ $role_slug ];
					}
				}
			}
		}

		$differences = array();

		foreach ( $expected as $key => $count ) {
			$reported = (int) ( 'total' === $key ? ( $counts['total_users'] ?? 0 ) : ( $counts['avail_roles'][ $key ] ?? 0 ) );

			if ( $reported !== $count ) {
				$differences[] = $key . ' reports ' . $reported . ' instead of ' . $count;
			}
		}

		return $differences;
	}

	/**
	 * Yields the scannable files under a code root in sorted depth-first order.
	 * Resuming after a path skips every subtree before it without reading it, so batches do not re-walk the root.
	 * Symbolic links and unreadable directories are yielded so the caller can report them.
	 *
	 * @param string $root         File or directory path.
	 * @param string $resume_after Path, relative to the root, of the last entry already scanned, or an empty string to start at the beginning.
	 * @return iterable<SplFileInfo>
	 */
	private function code_files( string $root, string $resume_after = '' ): iterable {
		if ( is_file( $root ) ) {
			$file = new SplFileInfo( $root );
			if ( $this->is_code_file( $file ) ) {
				yield $file;
			}
			return;
		}

		yield from $this->walk_directory(
			untrailingslashit( $root ),
			'' === $resume_after ? array() : explode( '/', $resume_after ),
			'uploads' === ( $this->root_kinds[ $root ] ?? '' )
		);
	}

	/**
	 * Walks one directory level in sorted order and recurses into subdirectories.
	 *
	 * @param string   $directory     Directory path, without a trailing slash.
	 * @param string[] $resume        Remaining path segments of the resume point below this directory.
	 * @param bool     $any_extension Whether files with non-code extensions are yielded.
	 * @return iterable<SplFileInfo>
	 */
	private function walk_directory( string $directory, array $resume, bool $any_extension ): iterable {
		$entries = is_readable( $directory ) ? scandir( $directory, SCANDIR_SORT_NONE ) : false;

		if ( false === $entries ) {
			yield new SplFileInfo( $directory );
			return;
		}

		sort( $entries, SORT_STRING );

		$resume_name = array_shift( $resume );

		foreach ( $entries as $entry ) {
			$entry        = (string) $entry;
			$child_resume = array();

			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}

			// Skip everything before the resume point and the resume entry itself, but descend into the directory that holds it.
			if ( null !== $resume_name ) {
				$order = strcmp( $entry, $resume_name );

				if ( $order < 0 || ( 0 === $order && ! $resume ) ) {
					continue;
				}

				$child_resume = 0 === $order ? $resume : array();
				$resume_name  = null;
			}

			$path       = $directory . '/' . $entry;
			$normalized = str_replace( '\\', '/', $path );
			$file       = new SplFileInfo( $path );

			foreach ( $this->excluded_paths as $excluded_path ) {
				if ( str_starts_with( $normalized . '/', $excluded_path ) ) {
					continue 2;
				}
			}

			if ( $file->isLink() ) {
				yield $file;
				continue;
			}

			if ( $file->isDir() ) {
				yield from $this->walk_directory( $path, $child_resume, $any_extension );
				continue;
			}

			if ( isset( $this->verified_own_files[ $normalized ] ) || ! $file->isFile() || ! $this->is_code_file( $file, $any_extension ) ) {
				continue;
			}

			yield $file;
		}
	}

	/**
	 * Verifies this plugin's own files against the checksums the release build writes.
	 * Matching files are skipped by the code scan; changed or unlisted files are reported and scanned.
	 * Without a checksums file, as in a development checkout, every file is scanned.
	 *
	 * @return array<string,bool> Normalized paths of the verified files.
	 */
	private function verify_own_files(): array {
		if ( ! defined( 'MODE_USER_SECURITY_VALIDATION_PATH' ) ) {
			return array();
		}

		$own_path       = trailingslashit( str_replace( '\\', '/', MODE_USER_SECURITY_VALIDATION_PATH ) );
		$checksums_file = $own_path . 'checksums.sha256';
		$contents       = is_readable( $checksums_file ) ? file_get_contents( $checksums_file ) : false; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads a local file.
		$checksums      = array();
		$verified       = array();

		if ( false === $contents ) {
			return $verified;
		}

		foreach ( (array) preg_split( '/\R/', $contents ) as $line ) {
			if ( preg_match( '/^([a-f0-9]{64})\s+\*?(\S+)$/i', trim( (string) $line ), $match ) ) {
				$checksums[ $match[2] ] = strtolower( $match[1] );
			}
		}

		foreach ( self::OWN_FILES as $own_file ) {
			$path = $own_path . $own_file;

			if ( ! is_file( $path ) ) {
				continue;
			}

			if ( isset( $checksums[ $own_file ] ) && hash_equals( $checksums[ $own_file ], (string) hash_file( 'sha256', $path ) ) ) {
				$verified[ $path ] = true;
				continue;
			}

			$this->root_findings[] = $this->finding(
				'high',
				'Plugin file does not match its release checksum',
				'File: ' . $this->relative_path( $path ) . '. The file differs from the released version, so it was added to the code scan.',
				'Compare the file with the released version, preserve it as evidence if the change is not approved, and reinstall the plugin from a trusted release.'
			);
		}

		return $verified;
	}

	/**
	 * Whether a file is a per-directory server configuration file: .htaccess or the PHP user INI file.
	 *
	 * @param SplFileInfo $file Candidate file.
	 * @return bool
	 */
	private function is_server_config_file( SplFileInfo $file ): bool {
		$user_ini_name = (string) ini_get( 'user_ini.filename' );
		$name          = $file->getFilename();

		return '.htaccess' === $name || ( '' !== $user_ini_name && $user_ini_name === $name );
	}

	/**
	 * Lists directives in a server configuration file that prepend code or change which files run as PHP.
	 * PHP-only handler assignments in the WordPress root are skipped because hosts set them there.
	 *
	 * @param string $contents  File contents.
	 * @param bool   $site_root Whether the file is in the WordPress root.
	 * @return array<int,array{severity:string,detail:string}>
	 */
	private function server_config_directives( string $contents, bool $site_root ): array {
		$directives = array();

		preg_match_all( '/^[ \t]*(?:php_(?:admin_)?value[ \t]+)?(auto_(?:prepend|append)_file)[ \t]*=?[ \t]*["\']?([^"\'\s;#]*)/mi', $contents, $prepends, PREG_SET_ORDER );

		foreach ( $prepends as $prepend ) {
			if ( '' === $prepend[2] || 'none' === strtolower( $prepend[2] ) ) {
				continue;
			}

			$directives[] = array(
				'severity' => 'high',
				'detail'   => 'Sets ' . strtolower( $prepend[1] ) . ' to ' . $prepend[2] . ', which runs that file on every PHP request in this directory',
			);
		}

		preg_match_all( '/^[ \t]*(AddHandler|AddType)[ \t]+(\S*(?:php|phtml)\S*)[ \t]+([^\r\n#]+)/mi', $contents, $handlers, PREG_SET_ORDER );

		foreach ( $handlers as $handler ) {
			$extensions = array_filter( array_map( static fn ( string $extension ): string => strtolower( ltrim( $extension, '.' ) ), (array) preg_split( '/\s+/', trim( $handler[3] ) ) ) );
			$non_php    = array_values( array_diff( $extensions, self::PHP_EXTENSIONS ) );

			if ( $non_php ) {
				$directives[] = array(
					'severity' => 'high',
					'detail'   => $handler[1] . ' runs non-PHP extensions as PHP: ' . $this->bounded_list( $non_php ),
				);
			} elseif ( ! $site_root ) {
				$directives[] = array(
					'severity' => 'medium',
					'detail'   => $handler[1] . ' assigns the PHP handler ' . $handler[2] . ' outside the WordPress root',
				);
			}
		}

		preg_match_all( '/^[ \t]*(SetHandler|ForceType)[ \t]+(\S*(?:php|phtml)\S*)/mi', $contents, $forced, PREG_SET_ORDER );

		foreach ( $site_root ? array() : $forced as $force ) {
			$directives[] = array(
				'severity' => 'high',
				'detail'   => $force[1] . ' forces matching files to run through the PHP handler ' . $force[2],
			);
		}

		return $directives;
	}

	/**
	 * Whether a file should be returned for scanning.
	 *
	 * PHP files are always returned so oversized ones can be reported; CSS and JS are size-limited.
	 * Other files are returned only when every extension is scanned, as in the uploads folder.
	 *
	 * @param SplFileInfo $file          Candidate file.
	 * @param bool        $any_extension Whether files with other extensions are returned.
	 * @return bool
	 */
	private function is_code_file( SplFileInfo $file, bool $any_extension = false ): bool {
		if ( $this->is_server_config_file( $file ) ) {
			return true;
		}

		$extension = strtolower( $file->getExtension() );

		if ( in_array( $extension, self::PHP_EXTENSIONS, true ) ) {
			return true;
		}

		if ( in_array( $extension, array( 'css', 'js' ), true ) ) {
			return $file->getSize() <= self::MAX_CODE_FILE_BYTES;
		}

		return $any_extension;
	}

	/**
	 * Returns a path relative to the WordPress root, or its basename when outside it.
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	private function relative_path( string $path ): string {
		$normalized = str_replace( '\\', '/', $path );
		$root       = trailingslashit( str_replace( '\\', '/', ABSPATH ) );

		if ( str_starts_with( $normalized, $root ) ) {
			return ltrim( substr( $normalized, strlen( $root ) ), '/' );
		}

		return wp_basename( $normalized );
	}

	/**
	 * Joins a sorted list, truncating it with a remaining count.
	 *
	 * @param string[] $values Values to list.
	 * @param int      $limit  Maximum values shown.
	 * @return string
	 */
	private function bounded_list( array $values, int $limit = 12 ): string {
		sort( $values );
		$visible   = array_slice( $values, 0, $limit );
		$remaining = count( $values ) - count( $visible );
		return implode( ', ', $visible ) . ( $remaining > 0 ? ' and ' . $remaining . ' more' : '' );
	}

	/**
	 * Builds a finding with a deterministic MUSV identifier.
	 *
	 * @param string $severity       critical, high, medium, low, or informational.
	 * @param string $title          Finding title.
	 * @param string $summary        Finding summary.
	 * @param string $recommendation Recommended investigation or remediation step.
	 * @param int    $user_id        Affected user ID, or 0 for a site-wide finding.
	 * @param string $user_login     Affected user login.
	 * @return array<string,mixed>
	 */
	private function finding(
		string $severity,
		string $title,
		string $summary,
		string $recommendation,
		int $user_id = 0,
		string $user_login = ''
	): array {
		if ( $this->site_id ) {
			$summary = 'Site: ' . $this->site_label . '. ' . $summary;
		}

		return array(
			'id'             => 'MUSV-' . strtoupper( substr( hash( 'sha256', implode( '|', array( $severity, $title, $summary, (string) $user_id ) ) ), 0, 10 ) ),
			'severity'       => $severity,
			'title'          => $title,
			'summary'        => $summary,
			'recommendation' => $recommendation,
			'user_id'        => $user_id,
			'user_login'     => $user_login,
			'site_id'        => $this->site_id,
		);
	}

	/**
	 * Removes findings with duplicate identifiers.
	 *
	 * @param array<int,array<string,mixed>> $findings Findings to deduplicate.
	 * @return array<int,array<string,mixed>>
	 */
	private function deduplicate_findings( array $findings ): array {
		$deduplicated = array();

		foreach ( $findings as $finding ) {
			$deduplicated[ $finding['id'] ] = $finding;
		}

		return array_values( $deduplicated );
	}
}
