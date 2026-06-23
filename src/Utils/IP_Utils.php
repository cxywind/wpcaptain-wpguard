<?php
/**
 * IP 工具类
 *
 * 提供获取客户端真实 IP、IP 范围匹配等辅助方法。
 *
 * @package WpGuard
 * @subpackage Utils
 */

namespace WpGuard\Utils;

/**
 * Class IP_Utils
 */
class IP_Utils {
    /**
     * 获取客户端真实 IP 地址
     *
     * 考虑常见代理/CDN 头信息（如 Cloudflare）。
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
     * 检查 IP 是否在指定的 CIDR 范围内
     *
     * @param string $ip   点分十进制 IP 地址
     * @param string $cidr CIDR 表示的网络（如 192.168.0.0/24）
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