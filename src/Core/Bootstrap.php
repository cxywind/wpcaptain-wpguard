<?php
namespace WpGuard\Core;

/**
 * Class Bootstrap
 * Main plugin bootstrap.
 */
class Bootstrap {
    use Singleton;

    /**
     * Constructor.
     */
    private function __construct() {
        // Load text domain.
        add_action( 'plugins_loaded', [ $this, 'load_textdomain' ] );
        // Initialize all modules after plugins loaded.
        add_action( 'plugins_loaded', [ $this, 'init_modules' ], 5 );
        // Register activation / deactivation hooks.
        register_activation_hook( WPGUARD_PATH . 'wpguard.php', [ $this, 'activate' ] );
        register_deactivation_hook( WPGUARD_PATH . 'wpguard.php', [ $this, 'deactivate' ] );
    }

    /**
     * Load plugin text domain.
     */
    public function load_textdomain() {
        load_plugin_textdomain( 'wpguard', false, dirname( plugin_basename( WPGUARD_PATH ) ) . '/languages' );
    }

    /**
     * Initialize core modules.
     */
    public function init_modules() {
        // Cache handler.
        \WpGuard\Cache\Cache_Handler::init();
        // Multisite compatibility.
        \WpGuard\Compatibility\Multisite::init();
        // Protection engine (front-end).
        \WpGuard\Protection\Protection_Engine::init();
        // Admin settings (if in admin area).
        if ( is_admin() ) {
            \WpGuard\Admin\Settings::init();
        }
        // Logger and daily cleanup cron.
        \WpGuard\Logger\Log_Handler::init();
        add_action( 'wpguard_daily_cleanup', [ '\WpGuard\Logger\Log_Handler', 'cleanup_logs' ] );
        if ( ! wp_next_scheduled( 'wpguard_daily_cleanup' ) ) {
            wp_schedule_event( time(), 'daily', 'wpguard_daily_cleanup' );
        }
    }

    /**
     * Plugin activation: create log table, set defaults.
     */
    public function activate() {
        \WpGuard\Logger\Log_Handler::create_table();
        // Set default network options if network activated.
        if ( is_multisite() && is_plugin_active_for_network( plugin_basename( WPGUARD_PATH . 'wpguard.php' ) ) ) {
            \WpGuard\Compatibility\Multisite::set_network_defaults();
        }
    }

    /**
     * Plugin deactivation: clean up cron.
     */
    public function deactivate() {
        wp_clear_scheduled_hook( 'wpguard_daily_cleanup' );
    }
}