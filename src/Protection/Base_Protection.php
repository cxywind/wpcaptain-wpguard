<?php
namespace WpGuard\Protection;

/**
 * Class Protection_Engine
 * Orchestrates all protection modules.
 */
class Protection_Engine {
    /**
     * Array of protection module instances.
     *
     * @var Base_Protection[]
     */
    private static $modules = [];

    /**
     * Initialize.
     */
    public static function init() {
        // Register modules.
        self::$modules[] = new Basic_Filter();
        self::$modules[] = new Path_Protect();
        // Hook early to intercept requests.
        add_action( 'plugins_loaded', [ __CLASS__, 'run_checks' ], 0 );
    }

    /**
     * Execute all protection checks.
     */
    public static function run_checks() {
        // Skip if in admin (allow backend access).
        if ( is_admin() ) {
            return;
        }
        // Skip cron and CLI.
        if ( defined( 'DOING_CRON' ) || defined( 'WP_CLI' ) ) {
            return;
        }
        foreach ( self::$modules as $module ) {
            if ( $module->check() ) {
                // Already blocked and died.
                exit;
            }
        }
    }
}