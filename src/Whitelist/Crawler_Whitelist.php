<?php
/**
 * 搜索引擎爬虫白名单验证
 *
 * 通过 IP 范围匹配和反向 DNS 验证，判断声称是爬虫的请求是否真实。
 *
 * @package WpGuard
 * @subpackage Whitelist
 */

namespace WpGuard\Whitelist;

/**
 * Class Crawler_Whitelist
 */
class Crawler_Whitelist {
    /**
     * 已知爬虫的 IP 范围（从配置文件加载）
     *
     * @var array
     */
    private static $ip_ranges = [];

    /**
     * 爬虫 UA 特征匹配模式
     *
     * @var array
     */
    private static $ua_patterns = [
        'googlebot'  => '/Googlebot/i',
        'bingbot'    => '/Bingbot/i',
        'yandexbot'  => '/YandexBot/i',
    ];

    /**
     * 初始化爬虫 IP 数据
     */
    public static function init() {
        if ( empty( self::$ip_ranges ) ) {
            $file = WPGUARD_PATH . 'includes/default-crawler-list.php';
            if ( file_exists( $file ) ) {
                self::$ip_ranges = include $file;
            }
        }
    }

    /**
     * 验证给定的 UA 和 IP 是否属于合法的搜索引擎爬虫
     *
     * @param string $ua 用户代理字符串
     * @param string $ip 客户端 IP
     * @return bool 合法返回 true
     */
    public static function is_legitimate_crawler( $ua, $ip ) {
        self::init();
        $crawler = null;
        foreach ( self::$ua_patterns as $name => $pattern ) {
            if ( preg_match( $pattern, $ua ) ) {
                $crawler = $name;
                break;
            }
        }
        if ( ! $crawler ) {
            return false;
        }
        return self::verify_ip( $ip, $crawler );
    }

    /**
     * 验证 IP 是否属于指定爬虫
     *
     * @param string $ip      IP 地址
     * @param string $crawler 爬虫标识
     * @return bool
     */
    private static function verify_ip( $ip, $crawler ) {
        // 先尝试静态 IP 范围匹配
        if ( isset( self::$ip_ranges[ $crawler ] ) ) {
            foreach ( self::$ip_ranges[ $crawler ] as $cidr ) {
                if ( \WpGuard\Utils\IP_Utils::ip_in_range( $ip, $cidr ) ) {
                    return true;
                }
            }
        }

        // Googlebot 可以额外使用反向 DNS 验证
        if ( 'googlebot' === $crawler ) {
            return self::reverse_dns_verify( $ip );
        }

        return false;
    }

    /**
     * 通过反向 DNS 和正向解析验证 Googlebot
     *
     * @param string $ip IP 地址
     * @return bool
     */
    private static function reverse_dns_verify( $ip ) {
        $hostname = gethostbyaddr( $ip );
        if ( ! $hostname || ( false === stripos( $hostname, '.googlebot.com' ) && false === stripos( $hostname, '.google.com' ) ) ) {
            return false;
        }
        $forward_ip = gethostbyname( $hostname );
        return $forward_ip === $ip;
    }
}