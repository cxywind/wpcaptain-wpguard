<?php
/**
 * Uninstall WpGuard.
 */
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

global $wpdb;

// Delete log table.
$table_name = $wpdb->prefix . 'wpguard_logs';
$wpdb->query( "DROP TABLE IF EXISTS $table_name" );

// Delete all options (single site and multisite).
$option_keys = [ 'basic_filter', 'path_protect', 'whitelist_logs' ];
foreach ( $option_keys as $key ) {
    delete_option( 'wpguard_' . $key );
    delete_option( 'wpguard_' . $key . '_custom' );
}
if ( is_multisite() ) {
    foreach ( $option_keys as $key ) {
        delete_site_option( 'wpguard_' . $key );
    }
}

// Clear scheduled hook.
wp_clear_scheduled_hook( 'wpguard_daily_cleanup' );