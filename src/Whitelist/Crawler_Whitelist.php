<?php
namespace WpGuard\Whitelist;

/**
 * Class Crawler_Whitelist
 * Validates whether a user-agent claiming to be a search engine is authentic.
 */
class Crawler_Whitelist {
    /**
     * Known crawler IP ranges (loaded from file).
     *
     * @var array
     */
    private static $ip_ranges = [];

    /**
     * Crawler user-agent signatures.
     *
     * @var array
     */
    private static $ua_patterns = [
        'googlebot'  => '/Googlebot/i',
        'bingbot'    => '/Bingbot/i',
        'yandexbot'  => '/YandexBot/i',
    ];

    /**
     * Initialize static data.
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
     * Verify if given UA/IP belong to a real search crawler.
     *
     * @param string $ua User agent string.
     * @param string $ip IP address.
     * @return bool True if verified as a legitimate crawler.
     */
    public static function is_legitimate_crawler( $ua, $ip ) {
        self::init();

        // Check if UA matches any crawler.
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

        // Verify IP against known ranges or reverse DNS.
        return self::verify_ip( $ip, $crawler );
    }

    /**
     * Verify IP belongs to crawler.
     *
     * @param string $ip      IP.
     * @param string $crawler Crawler identifier.
     * @return bool
     */
    private static function verify_ip( $ip, $crawler ) {
        // Check static IP ranges first.
        if ( isset( self::$ip_ranges[ $crawler ] ) ) {
            foreach ( self::$ip_ranges[ $crawler ] as $cidr ) {
                if ( \WpGuard\Utils\IP_Utils::ip_in_range( $ip, $cidr ) ) {
                    return true;
                }
            }
        }

        // Reverse DNS verification for Googlebot (fallback).
        if ( 'googlebot' === $crawler ) {
            return self::reverse_dns_verify( $ip );
        }

        // If not in static list and no DNS method, assume false.
        return false;
    }

    /**
     * Verify Googlebot via reverse DNS.
     *
     * @param string $ip IP.
     * @return bool
     */
    private static function reverse_dns_verify( $ip ) {
        $hostname = gethostbyaddr( $ip );
        if ( ! $hostname || false === stripos( $hostname, '.googlebot.com' ) && false === stripos( $hostname, '.google.com' ) ) {
            return false;
        }
        $forward_ip = gethostbyname( $hostname );
        return $forward_ip === $ip;
    }
}