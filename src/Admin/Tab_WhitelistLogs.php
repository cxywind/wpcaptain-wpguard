<?php
namespace WpGuard\Admin;

/**
 * Class Tab_WhitelistLogs
 * Placeholder for whitelist and logs.
 */
class Tab_WhitelistLogs extends Tab_Base {
    /**
     * Constructor.
     */
    public function __construct() {
        $this->slug       = 'whitelist_logs';
        $this->title      = __( 'Whitelist & Logs', 'wpguard' );
        $this->option_key = 'whitelist_logs';
        $this->defaults   = [];
    }

    /**
     * Render tab content.
     */
    public function render() {
        $log_count = \WpGuard\Logger\Log_Handler::get_log_count();
        ?>
        <div class="wrap">
            <h3><?php esc_html_e( 'Log Overview', 'wpguard' ); ?></h3>
            <p><?php echo esc_html( sprintf( __( 'Total blocked requests in log: %d', 'wpguard' ), $log_count ) ); ?></p>
            <p><?php esc_html_e( 'Logs are automatically cleaned after 30 days.', 'wpguard' ); ?></p>
            <p><em><?php esc_html_e( 'Full log viewer and whitelist management will be available in a future version.', 'wpguard' ); ?></em></p>
        </div>
        <?php
    }
}