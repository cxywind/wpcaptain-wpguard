<?php
namespace WpGuard\Utils;

/**
 * Class IP_Utils
 * Utilities for IP address handling.
 */
class IP_Utils {
    /**
     * Get the client IP address.
     *
     * @return string
     */
    public static function get_ip() {
        $headers = [
            'HTTP_CF_CONNECTING_IP', // Cloudflare
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_CLIENT_IP',
            'REMOTE_ADDR',
        ];
        foreach ( $headers as $header ) {
            if ( ! empty( $_SERVER[ $header ] ) ) {
                $ip = trim( $_SERVER[ $header ] );
                if ( false !== filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                    return $ip;
                }
            }
        }
        return '0.0.0.0';
    }

    /**
     * Check if an IP is in a given CIDR range.
     *
     * @param string $ip   IP address.
     * @param string $cidr CIDR notation (e.g., 192.168.0.0/24).
     * @return bool
     */
    public static function ip_in_range( $ip, $cidr ) {
        list( $subnet, $bits ) = explode( '/', $cidr );
        if ( ! $bits ) {
            return $ip === $cidr;
        }
        $ip_long    = ip2long( $ip );
        $subnet_long = ip2long( $subnet );
        $mask = -1 << ( 32 - (int) $bits );
        return ( $ip_long & $mask ) === ( $subnet_long & $mask );
    }
}