<?php
/**
 * Googlebot 真实性验证器
 *
 * 通过反向DNS + 正向DNS双重验证确认访客是否为真实的 Googlebot。
 * 验证结果缓存 24 小时，避免重复查询。
 *
 * @package WpGuard
 * @subpackage Utils
 */

namespace WpGuard\Utils;

/**
 * Class Googlebot_Verifier
 */
class Googlebot_Verifier {

    /**
     * 验证访客是否为真实的 Googlebot
     *
     * @param string $ip       访客 IP 地址
     * @param string $ua       User-Agent 字符串
     * @param bool   $use_cache 是否使用缓存（默认 true）
     * @return bool true=真实Googlebot或非Googlebot（无需拦截）, false=伪造Googlebot
     */
    public static function is_googlebot( $ip, $ua, $use_cache = true ) {
        // 如果 UA 不包含 Googlebot，不验证，直接放行
        if ( stripos( $ua, 'Googlebot' ) === false ) {
            return true;
        }

        if ( $use_cache ) {
            // 检查缓存
            $cache_key = 'googlebot_' . $ip;
            $cached    = \WpGuard\Cache\Cache_Handler::get( $cache_key );
            if ( false !== $cached ) {
                return (bool) $cached;
            }
        }

        // 执行反向 DNS 验证
        $is_valid = self::verify_by_dns( $ip );

        if ( $use_cache ) {
        // 缓存结果 24 小时
        \WpGuard\Cache\Cache_Handler::set( $cache_key, $is_valid ? 1 : 0, DAY_IN_SECONDS );
    }

        return $is_valid;
    }

    /**
     * 通过 DNS 验证 Googlebot 真实性
     *
     * @param string $ip 访客 IP
     * @return bool
     */
    private static function verify_by_dns( $ip ) {
        // 反向 DNS：获取 IP 的 PTR 记录
        $hostname = gethostbyaddr( $ip );
        if ( ! $hostname || $hostname === $ip ) {
            return false;
        }

        // 检查 PTR 记录是否属于 Google 的域名
        $hostname_lower = strtolower( $hostname );
        if ( substr_compare( $hostname_lower, '.googlebot.com', -strlen( '.googlebot.com' ) ) !== 0
            && substr_compare( $hostname_lower, '.google.com', -strlen( '.google.com' ) ) !== 0 ) {
            return false;
        }

        // 正向 DNS：解析 PTR 记录对应的 IP
        $resolved_ip = gethostbyname( $hostname );
        if ( ! $resolved_ip || $resolved_ip === $hostname ) {
            return false;
        }

        // 验证 IP 是否一致
        return $resolved_ip === $ip;
    }
}

