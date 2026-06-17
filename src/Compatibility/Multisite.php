<?php
namespace WpGuard\Compatibility;

/**
 * Class Multisite
 * Handles multisite option inheritance and overriding.
 */
class Multisite {
    /**
     * Flag indicating if we are in a network context.
     *
     * @var bool|null
     */
    private static $is_network_active = null;

    /**
     * Init.
     */
    public static function init() {
        // Nothing to do now.
    }

    /**
     * Check if plugin is network activated.
     *
     * @return bool
     */
    public static function is_network_activated() {
        if ( is_null( self::$is_network_active ) ) {
            if ( ! is_multisite() ) {
                self::$is_network_active = false;
            } else {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
                self::$is_network_active = is_plugin_active_for_network( plugin_basename( WPGUARD_PATH . 'wpguard.php' ) );
            }
        }
        return self::$is_network_active;
    }

    /**
     * Get option value considering multisite inheritance.
     *
     * @param string $key      Option key without prefix.
     * @param mixed  $default  Default value.
     * @return mixed
     */
    public static function get_option( $key, $default = [] ) {
        $option_name = 'wpguard_' . $key;

        if ( self::is_network_activated() ) {
            // In network mode, check if current site has custom value.
            if ( get_option( $option_name . '_custom' ) ) {
                $value = get_option( $option_name, null );
                if ( ! is_null( $value ) ) {
                    return $value;
                }
            }
            // Fallback to network default.
            return get_site_option( $option_name, $default );
        }

        // Single site or network-activated but not handled? Actually just single.
        return get_option( $option_name, $default );
    }

    /**
     * Update option for the current context.
     *
     * @param string $key   Option key without prefix.
     * @param mixed  $value Value.
     */
    public static function update_option( $key, $value ) {
        $option_name = 'wpguard_' . $key;

        if ( self::is_network_activated() && is_network_admin() ) {
            update_site_option( $option_name, $value );
        } else {
            // When saving in a subsite, mark as custom and save.
            update_option( $option_name . '_custom', 1 );
            update_option( $option_name, $value );
        }
    }

    /**
     * Delete a site-level custom option to restore inheritance.
     *
     * @param string $key Option key without prefix.
     */
    public static function delete_option( $key ) {
        $option_name = 'wpguard_' . $key;
        delete_option( $option_name );
        delete_option( $option_name . '_custom' );
    }

    /**
     * Set network defaults on plugin network activation.
     */
    public static function set_network_defaults() {
        // Set basic filter defaults.
        update_site_option( 'wpguard_basic_filter', [
            'enable_empty_ua'        => 1,
            'enable_fake_crawler'    => 1,
            'enable_header_check'    => 1,
            'enable_referer_check'   => 0,
        ] );
        // Set path protection defaults.
        update_site_option( 'wpguard_path_protect', [
            'enable_sensitive_files'  => 1,
            'enable_backup_files'     => 1,
            'allowed_download_dirs'   => '',
            'enable_custom_keywords'  => 0,
            'custom_keywords'         => '',
        ] );
    }
}