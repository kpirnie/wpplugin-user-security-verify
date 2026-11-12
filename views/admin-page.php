<?php
/**
 * Administrator scan page.
 *
 * @package Mode\UserSecurityValidation
 * @author Kevin Brent
 */

namespace Mode\UserSecurityValidation;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wrap mode-usv" id="mode-usv-app">
	<div class="mode-usv__header">
		<div>
			<p class="mode-usv__eyebrow"><?php esc_html_e( 'ModeEffect Security', 'mode-user-security-validation' ); ?></p>
			<h1><?php esc_html_e( 'User Security Validation', 'mode-user-security-validation' ); ?></h1>
			<p class="mode-usv__intro">
				<?php esc_html_e( 'Run a read-only review of users, roles, direct capabilities, sessions, application passwords, visibility filters, registration patterns, and user-related code paths. Database records are authoritative; WordPress user queries are used only to expose filtering differences.', 'mode-user-security-validation' ); ?>
			</p>
		</div>
		<div class="mode-usv__shield" aria-hidden="true">ME</div>
	</div>

	<div class="notice notice-warning inline mode-usv__notice">
		<p>
			<strong><?php esc_html_e( 'Review required:', 'mode-user-security-validation' ); ?></strong>
			<?php esc_html_e( 'Findings are indicators, not automatic proof of compromise. This plugin does not change or delete users.', 'mode-user-security-validation' ); ?>
		</p>
	</div>

	<div class="mode-usv__severity-guide" aria-label="<?php esc_attr_e( 'Severity guide', 'mode-user-security-validation' ); ?>">
		<span><b class="mode-usv__badge mode-usv__badge--critical"><?php esc_html_e( 'Critical', 'mode-user-security-validation' ); ?></b> <?php esc_html_e( 'Immediate hidden privilege or persistence risk', 'mode-user-security-validation' ); ?></span>
		<span><b class="mode-usv__badge mode-usv__badge--high"><?php esc_html_e( 'High', 'mode-user-security-validation' ); ?></b> <?php esc_html_e( 'Strong privilege or integrity anomaly', 'mode-user-security-validation' ); ?></span>
		<span><b class="mode-usv__badge mode-usv__badge--medium"><?php esc_html_e( 'Medium', 'mode-user-security-validation' ); ?></b> <?php esc_html_e( 'Suspicious condition requiring review', 'mode-user-security-validation' ); ?></span>
		<span><b class="mode-usv__badge mode-usv__badge--low"><?php esc_html_e( 'Low', 'mode-user-security-validation' ); ?></b> <?php esc_html_e( 'Weak indicator or account hygiene issue', 'mode-user-security-validation' ); ?></span>
		<span><b class="mode-usv__badge mode-usv__badge--informational"><?php esc_html_e( 'Info', 'mode-user-security-validation' ); ?></b> <?php esc_html_e( 'Context for manual investigation', 'mode-user-security-validation' ); ?></span>
	</div>

	<div class="mode-usv__controls">
		<button type="button" class="button button-primary button-hero" id="mode-usv-start">
			<?php esc_html_e( 'Run User Security Scan', 'mode-user-security-validation' ); ?>
		</button>
		<button type="button" class="button" id="mode-usv-cancel" disabled>
			<?php esc_html_e( 'Cancel', 'mode-user-security-validation' ); ?>
		</button>
		<button type="button" class="button" id="mode-usv-download" disabled>
			<?php esc_html_e( 'Download JSON Results', 'mode-user-security-validation' ); ?>
		</button>
	</div>

	<section class="mode-usv__progress-panel" aria-labelledby="mode-usv-progress-heading">
		<div class="mode-usv__progress-heading">
			<h2 id="mode-usv-progress-heading"><?php esc_html_e( 'Scan Progress', 'mode-user-security-validation' ); ?></h2>
			<span id="mode-usv-progress-label">0%</span>
		</div>
		<div class="mode-usv__progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
			<span id="mode-usv-progress-bar"></span>
		</div>
		<ol class="mode-usv__test-list" id="mode-usv-test-list"></ol>
	</section>

	<section class="mode-usv__results" id="mode-usv-results" hidden>
		<h2><?php esc_html_e( 'Results', 'mode-user-security-validation' ); ?></h2>
		<p><?php esc_html_e( 'Each affected user appears once with all related findings grouped below it. Severity totals count affected users plus separate site-wide findings.', 'mode-user-security-validation' ); ?></p>
		<div class="mode-usv__summary" id="mode-usv-summary"></div>
		<div class="mode-usv__empty" id="mode-usv-empty" hidden></div>
		<div class="mode-usv__table-wrap">
			<table class="widefat striped mode-usv__findings-table" id="mode-usv-findings-table">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Severity', 'mode-user-security-validation' ); ?></th>
						<th><?php esc_html_e( 'Finding', 'mode-user-security-validation' ); ?></th>
						<th><?php esc_html_e( 'User', 'mode-user-security-validation' ); ?></th>
						<th><?php esc_html_e( 'Evidence and recommendation', 'mode-user-security-validation' ); ?></th>
					</tr>
				</thead>
				<tbody></tbody>
			</table>
		</div>
	</section>

	<section class="mode-usv__inventory" id="mode-usv-inventory" hidden>
		<h2><?php esc_html_e( 'Users With Issues', 'mode-user-security-validation' ); ?></h2>
		<p><?php esc_html_e( 'Normal users are excluded. Email addresses, password hashes, session tokens, and application-password values are not displayed.', 'mode-user-security-validation' ); ?></p>
		<div class="mode-usv__table-wrap">
			<table class="widefat striped" id="mode-usv-users-table">
				<thead>
					<tr>
						<th><?php esc_html_e( 'ID', 'mode-user-security-validation' ); ?></th>
						<th><?php esc_html_e( 'Login', 'mode-user-security-validation' ); ?></th>
						<th><?php esc_html_e( 'Roles', 'mode-user-security-validation' ); ?></th>
						<th><?php esc_html_e( 'Registered (UTC)', 'mode-user-security-validation' ); ?></th>
						<th><?php esc_html_e( 'Direct caps', 'mode-user-security-validation' ); ?></th>
						<th><?php esc_html_e( 'Sensitive caps', 'mode-user-security-validation' ); ?></th>
						<th><?php esc_html_e( 'Sessions', 'mode-user-security-validation' ); ?></th>
						<th><?php esc_html_e( 'App passwords', 'mode-user-security-validation' ); ?></th>
						<th><?php esc_html_e( 'Content / customer', 'mode-user-security-validation' ); ?></th>
					</tr>
				</thead>
				<tbody></tbody>
			</table>
		</div>
	</section>
</div>
