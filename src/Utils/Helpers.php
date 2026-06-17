<?php
namespace WpGuard\Utils;

/**
 * Class Helpers
 * Miscellaneous helper methods.
 */
class Helpers {
    /**
     * Get plugin option with network inheritance.
     *
     * @param string $key     Settings group key.
     * @param mixed  $default Default.
     * @return array
     */
    public static function get_settings( $key, $default = [] ) {
        return \WpGuard\Compatibility\Multisite::get_option( $key, $default );
    }

    /**
     * Update plugin settings.
     *
     * @param string $key   Settings group key.
     * @param mixed  $value Value.
     */
    public static function update_settings( $key, $value ) {
        \WpGuard\Compatibility\Multisite::update_option( $key, $value );
    }

    /**
     * Get risk level for a feature.
     *
     * @param string $feature Feature slug.
     * @return string 'high', 'medium', 'low', 'none'
     */
    public static function get_risk_level( $feature ) {
        $risks = [
            'empty_ua'          => 'low',
            'fake_crawler'      => 'none',
            'header_check'      => 'low',
            'referer_check'     => 'low',
            'sensitive_files'   => 'none',
            'backup_files'      => 'none',
            'custom_keywords'   => 'low',
        ];
        return isset( $risks[ $feature ] ) ? $risks[ $feature ] : 'low';
    }
}