<?php
/**
 * Plugin bootstrap and administrator interface controller.
 *
 * @package Mode\UserSecurityValidation
 * @author Kevin Brent
 */

namespace Mode\UserSecurityValidation;

use RuntimeException;
use Throwable;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registers the administration pages, assets, and AJAX scan handler.
 */
final class Plugin {
	private const PAGE_SLUG          = 'mode-user-security-validation';
	private const CAPABILITY         = 'manage_options';
	private const NETWORK_CAPABILITY = 'manage_network_options';
	private const AJAX_ACTION        = 'mode_usv_run_test';
	private const NONCE_ACTION       = 'mode_usv_scan';

	/**
	 * Shared instance.
	 *
	 * @var Plugin|null
	 */
	private static ?Plugin $instance = null;

	/**
	 * Hook suffix of the registered scan page.
	 *
	 * @var string
	 */
	private string $page_hook = '';

	/**
	 * Scope of the registered scan page: 'site' or 'network'.
	 *
	 * @var string
	 */
	private string $page_scope = 'site';

	/**
	 * Returns the shared plugin instance.
	 *
	 * @return Plugin
	 */
	public static function instance(): Plugin {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Registers the administration hooks.
	 */
	private function __construct() {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'network_admin_menu', array( $this, 'register_network_menu' ) );
		add_filter(
			'network_admin_plugin_action_links_' . plugin_basename( MODE_USER_SECURITY_VALIDATION_PATH . 'mode-user-security-validation.php' ),
			array( $this, 'add_network_plugin_action_links' )
		);
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'wp_ajax_' . self::AJAX_ACTION, array( $this, 'ajax_run_test' ) );
		add_filter(
			'plugin_action_links_' . plugin_basename( MODE_USER_SECURITY_VALIDATION_PATH . 'mode-user-security-validation.php' ),
			array( $this, 'add_plugin_action_links' )
		);
	}

	/**
	 * Adds a direct link from the Plugins list to the security audit page.
	 *
	 * @param string[] $links Existing plugin action links.
	 * @return string[]
	 */
	public function add_plugin_action_links( array $links ): array {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			return $links;
		}

		array_unshift(
			$links,
			sprintf(
				'<a href="%s">%s</a>',
				esc_url( admin_url( 'users.php?page=' . self::PAGE_SLUG ) ),
				esc_html__( 'Audit', 'mode-user-security-validation' )
			)
		);

		return $links;
	}

	/**
	 * Adds a direct link from the Network Plugins list to the network security audit page.
	 *
	 * @param string[] $links Existing plugin action links.
	 * @return string[]
	 */
	public function add_network_plugin_action_links( array $links ): array {
		if ( ! current_user_can( self::NETWORK_CAPABILITY ) ) {
			return $links;
		}

		array_unshift(
			$links,
			sprintf(
				'<a href="%s">%s</a>',
				esc_url( network_admin_url( 'users.php?page=' . self::PAGE_SLUG ) ),
				esc_html__( 'Audit', 'mode-user-security-validation' )
			)
		);

		return $links;
	}

	/**
	 * Registers the Users screen page.
	 *
	 * @return void
	 */
	public function register_menu(): void {
		$this->page_hook = (string) add_users_page(
			__( 'User Security Validation', 'mode-user-security-validation' ),
			__( 'Security Validation', 'mode-user-security-validation' ),
			$this->capability( $this->page_scope ),
			self::PAGE_SLUG,
			array( $this, 'render_page' )
		);
	}

	/**
	 * Registers the network Users screen page for super administrators.
	 *
	 * @return void
	 */
	public function register_network_menu(): void {
		$this->page_scope = 'network';
		$this->register_menu();
	}

	/**
	 * Enqueues the scan page assets and the localized scan configuration.
	 *
	 * @param string $hook_suffix Current administration page hook.
	 * @return void
	 */
	public function enqueue_assets( string $hook_suffix ): void {
		if ( $this->page_hook !== $hook_suffix ) {
			return;
		}

		wp_enqueue_style(
			'mode-user-security-validation',
			MODE_USER_SECURITY_VALIDATION_URL . 'assets/admin.css',
			array(),
			MODE_USER_SECURITY_VALIDATION_VERSION
		);

		wp_enqueue_script(
			'mode-user-security-validation',
			MODE_USER_SECURITY_VALIDATION_URL . 'assets/admin.js',
			array(),
			MODE_USER_SECURITY_VALIDATION_VERSION,
			true
		);

		wp_localize_script(
			'mode-user-security-validation',
			'ModeUserSecurityValidation',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'action'  => self::AJAX_ACTION,
				'nonce'   => wp_create_nonce( $this->nonce_action( $this->page_scope ) ),
				'scope'   => $this->page_scope,
				'sites'   => $this->network_sites(),
				'version' => MODE_USER_SECURITY_VALIDATION_VERSION,
				'tests'   => Scan_Runner::manifest( $this->page_scope ),
				'labels'  => array(
					'running'       => __( 'Running', 'mode-user-security-validation' ),
					'complete'      => __( 'Complete', 'mode-user-security-validation' ),
					'failed'        => __( 'Failed', 'mode-user-security-validation' ),
					'cancelled'     => __( 'Cancelled', 'mode-user-security-validation' ),
					'noFindings'    => __( 'No potential security issues were identified by the completed tests.', 'mode-user-security-validation' ),
					'requestFailed' => __( 'The test request failed. Review the browser console and WordPress error log.', 'mode-user-security-validation' ),
				),
			)
		);
	}

	/**
	 * Renders the scan page.
	 *
	 * @return void
	 */
	public function render_page(): void {
		if ( ! current_user_can( $this->capability( $this->page_scope ) ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'mode-user-security-validation' ) );
		}

		require MODE_USER_SECURITY_VALIDATION_PATH . 'views/admin-page.php';
	}

	/**
	 * Runs one validation test for an authorized, nonce-verified AJAX request.
	 *
	 * @return void
	 * @throws RuntimeException When a network test names a site outside this network; caught and returned as a JSON error.
	 */
	public function ajax_run_test(): void {
		$scope = is_multisite() && isset( $_POST['scope'] ) && 'network' === sanitize_key( wp_unslash( $_POST['scope'] ) ) ? 'network' : 'site';

		if ( ! current_user_can( $this->capability( $scope ) ) ) {
			wp_send_json_error(
				array( 'message' => __( 'You do not have permission to run this scan.', 'mode-user-security-validation' ) ),
				403
			);
		}

		check_ajax_referer( $this->nonce_action( $scope ), 'nonce' );

		$test_id     = isset( $_POST['test_id'] ) ? sanitize_key( wp_unslash( $_POST['test_id'] ) ) : '';
		$site_id     = isset( $_POST['site_id'] ) ? absint( wp_unslash( $_POST['site_id'] ) ) : 0;
		$cursor_path = isset( $_POST['cursor_path'] ) && is_string( $_POST['cursor_path'] ) ? str_replace( chr( 0 ), '', wp_unslash( $_POST['cursor_path'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- A relative file path; sanitize_text_field() would corrupt it. Null bytes are stripped and traversal segments are rejected below.
		$cursor      = array(
			'root' => isset( $_POST['cursor_root'] ) ? absint( wp_unslash( $_POST['cursor_root'] ) ) : 0,
			'path' => preg_match( '#(?:^|/)\.\.(?:/|$)#', $cursor_path ) ? '' : $cursor_path,
		);
		$switched    = false;

		try {
			if ( 'network' === $scope && 'site' === Scan_Runner::test_scope( $test_id ) ) {
				$site_ids = array_map( 'intval', array_column( ( new Scan_Runner( $scope ) )->network_sites(), 'blog_id' ) );

				if ( ! in_array( $site_id, $site_ids, true ) ) {
					throw new RuntimeException( 'Unknown network site.' );
				}

				$switched = switch_to_blog( $site_id );
			}

			$runner = new Scan_Runner( $scope );
			$result = $runner->run( $test_id, $cursor );

			if ( $switched ) {
				restore_current_blog();
			}

			wp_send_json_success( $result );
		} catch ( Throwable $exception ) {
			if ( $switched ) {
				restore_current_blog();
			}

			error_log( // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Records failed scan tests for administrators.
				sprintf(
					'[mode-user-security-validation] Test "%s" on site %d failed: %s: %s in %s:%d',
					$test_id,
					$site_id,
					get_class( $exception ),
					$exception->getMessage(),
					$exception->getFile(),
					$exception->getLine()
				)
			);

			wp_send_json_error(
				array(
					'message' => __( 'The test could not be completed.', 'mode-user-security-validation' ),
					'test_id' => $test_id,
					'site_id' => $site_id,
				),
				500
			);
		}
	}

	/**
	 * Returns the capability required for a scan scope.
	 *
	 * @param string $scope 'site' or 'network'.
	 * @return string
	 */
	private function capability( string $scope ): string {
		return 'network' === $scope ? self::NETWORK_CAPABILITY : self::CAPABILITY;
	}

	/**
	 * Returns the nonce action for a scan scope.
	 *
	 * @param string $scope 'site' or 'network'.
	 * @return string
	 */
	private function nonce_action( string $scope ): string {
		return 'network' === $scope ? self::NONCE_ACTION . '_network' : self::NONCE_ACTION;
	}

	/**
	 * Lists the network's sites for the network scan.
	 *
	 * @return array<int,array{id:int,label:string}>
	 */
	private function network_sites(): array {
		if ( 'network' !== $this->page_scope ) {
			return array();
		}

		try {
			$runner = new Scan_Runner( 'network' );
		} catch ( Throwable $exception ) {
			return array();
		}

		return array_map(
			static fn ( array $site ): array => array(
				'id'    => (int) $site['blog_id'],
				'label' => (string) $site['label'],
			),
			$runner->network_sites()
		);
	}
}
