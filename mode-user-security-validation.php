<?php
/**
 * Plugin Name:  ModeEffect User Security Validation
 * Plugin URI:   https://modeeffect.com
 * Description:  Read-only validation of WordPress users, roles, capabilities, sessions, application passwords, visibility, and user-related code paths.
 * Version:      1.1.38
 * Author:       ModeEffect
 * Author URI:   https://modeeffect.com
 * Contributors: Kevin Brent, Kevin Pirnie
 * License:      GPLv2 or later
 * License URI:  https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:  mode-user-security-validation
 * Requires at least: 6.7
 * Requires PHP: 8.0
 *
 * @package Mode\UserSecurityValidation
 * @author Kevin Brent
 */

namespace Mode\UserSecurityValidation;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'MODE_USER_SECURITY_VALIDATION_VERSION', '1.1.38' );
define( 'MODE_USER_SECURITY_VALIDATION_PATH', plugin_dir_path( __FILE__ ) );
define( 'MODE_USER_SECURITY_VALIDATION_URL', plugin_dir_url( __FILE__ ) );

require_once MODE_USER_SECURITY_VALIDATION_PATH . 'includes/class-scan-runner.php';
require_once MODE_USER_SECURITY_VALIDATION_PATH . 'includes/class-plugin.php';

Plugin::instance();
