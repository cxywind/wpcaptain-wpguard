<?php
namespace WpGuard\Protection;

/**
 * Class Basic_Filter
 * Filters requests based on UA, headers, and crawler validity.
 */
class Basic_Filter extends Base_Protection {
    /**
     * Settings array.
     *
     * @var array
     */
    private $settings;

    /**
     * Constructor.
     */
    public function __construct() {
        $this->settings = \WpGuard\Utils\Helpers::get_settings( 'basic_filter', [
            'enable_empty_ua'      => 1,
            'enable_fake_crawler'  => 1,
            'enable_header_check'  => 1,
            'enable_referer_check' => 0,
        ] );
    }

    /**
     * Run checks. Return true to block.
     *
     * @return bool
     */
    public function check() {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $ip = \WpGuard\Utils\IP_Utils::get_ip();

        // Empty user-agent.
        if ( $this->settings['enable_empty_ua'] && $this->is_empty_ua( $ua ) ) {
            $this->block( 'Empty User-Agent' );
            return true;
        }

        // Fake crawler detection.
        if ( $this->settings['enable_fake_crawler'] && \WpGuard\Whitelist\Crawler_Whitelist::is_fake_crawler( $ua, $ip ) ) {
            $this->block( 'Fake Crawler' );
            return true;
        }

        // Missing common headers.
        if ( $this->settings['enable_header_check'] && ! $this->has_valid_headers() ) {
            $this->block( 'Missing Headers' );
            return true;
        }

        // Referer check on sensitive pages (wp-login.php, wp-admin).
        if ( $this->settings['enable_referer_check'] && $this->is_sensitive_page() && $this->has_invalid_referer() ) {
            $this->block( 'Invalid Referer' );
            return true;
        }

        return false;
    }

    /**
     * Check if UA is empty or too short.
     *
     * @param string $ua User agent.
     * @return bool
     */
    private function is_empty_ua( $ua ) {
        return strlen( trim( $ua ) ) < 3;
    }

    /**
     * Check if crawler is legitimate (delegates to Crawler_Whitelist).
     *
     * @param string $ua User agent.
     * @param string $ip IP.
     * @return bool True if fake.
     */
    public static function is_fake_crawler( $ua, $ip ) {
        // Check common crawler patterns.
        $crawlers = [ 'googlebot', 'bingbot', 'yandexbot', 'baiduspider', 'duckduckbot' ];
        foreach ( $crawlers as $crawler ) {
            if ( stripos( $ua, $crawler ) !== false ) {
                return ! \WpGuard\Whitelist\Crawler_Whitelist::is_legitimate_crawler( $ua, $ip );
            }
        }
        return false;
    }

    /**
     * Check for presence of standard browser headers.
     *
     * @return bool
     */
    private function has_valid_headers() {
        $required = [ 'HTTP_ACCEPT', 'HTTP_ACCEPT_LANGUAGE', 'HTTP_ACCEPT_ENCODING' ];
        foreach ( $required as $header ) {
            if ( empty( $_SERVER[ $header ] ) ) {
                return false;
            }
        }
        return true;
    }

    /**
     * Check if current page is sensitive (wp-login, admin).
     *
     * @return bool
     */
    private function is_sensitive_page() {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        return (bool) preg_match( '#/wp-(login|admin)#i', $uri );
    }

    /**
     * Check if referer is invalid.
     *
     * @return bool True if invalid.
     */
    private function has_invalid_referer() {
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        if ( empty( $referer ) ) {
            return true;
        }
        $site_url = site_url();
        return 0 !== strpos( $referer, $site_url );
    }

    /**
     * Block request, log, and exit.
     *
     * @param string $reason Reason for block.
     * @param int    $code   HTTP status code.
     */
    private function block( $reason, $code = 403 ) {
        \WpGuard\Logger\Log_Handler::log( [
            'reason'      => $reason,
            'status_code' => $code,
        ] );
        status_header( $code );
        die( 'Access denied.' );
    }
}