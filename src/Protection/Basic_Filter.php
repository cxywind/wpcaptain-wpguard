<?php
/**
 * 基础请求过滤模块
 *
 * 基于 User-Agent、请求头和爬虫验证来拦截可疑请求。
 *
 * @package WpGuard
 * @subpackage Protection
 */

namespace WpGuard\Protection;

/**
 * Class Basic_Filter
 */
class Basic_Filter extends Base_Protection {
    /**
     * 当前生效的设置
     *
     * @var array
     */
    private $settings;

    /**
     * 构造函数：加载设置
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
     * 执行全部基础过滤检查
     *
     * @return bool
     */
    public function check() {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $ip = \WpGuard\Utils\IP_Utils::get_ip();

        // 1. 空 UA 检测
        if ( $this->settings['enable_empty_ua'] && $this->is_empty_ua( $ua ) ) {
            $this->block( '空 User-Agent' );
            return true;
        }

        // 2. 伪造爬虫检测
        if ( $this->settings['enable_fake_crawler'] && $this->is_fake_crawler( $ua, $ip ) ) {
            $this->block( '伪造爬虫' );
            return true;
        }

        // 3. 缺失标准头检测
        if ( $this->settings['enable_header_check'] && ! $this->has_valid_headers() ) {
            $this->block( '缺失请求头' );
            return true;
        }

        // 4. Referer 检测（仅敏感页面）
        if ( $this->settings['enable_referer_check'] && $this->is_sensitive_page() && $this->has_invalid_referer() ) {
            $this->block( '非法 Referer' );
            return true;
        }

        return false;
    }

    /**
     * 检查 UA 是否为空或过短
     *
     * @param string $ua User-Agent 字符串
     * @return bool
     */
    private function is_empty_ua( $ua ) {
        return strlen( trim( $ua ) ) < 3;
    }

    /**
     * 检查是否为伪造的搜索引擎爬虫
     *
     * @param string $ua User-Agent
     * @param string $ip 客户端 IP
     * @return bool 是伪造返回 true
     */
    private function is_fake_crawler( $ua, $ip ) {
        $crawlers = [ 'googlebot', 'bingbot', 'yandexbot', 'baiduspider', 'duckduckbot' ];
        foreach ( $crawlers as $crawler ) {
            if ( stripos( $ua, $crawler ) !== false ) {
                return ! \WpGuard\Whitelist\Crawler_Whitelist::is_legitimate_crawler( $ua, $ip );
            }
        }
        return false;
    }

    /**
     * 检查是否包含标准浏览器请求头
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
     * 判断当前请求是否为敏感页面（登录、后台）
     *
     * @return bool
     */
    private function is_sensitive_page() {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        return (bool) preg_match( '#/wp-(login|admin)#i', $uri );
    }

    /**
     * 检查 Referer 是否无效（空或外部来源）
     *
     * @return bool
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
     * 执行拦截：记录日志并终止请求
     *
     * @param string $reason 拦截原因
     * @param int    $code   HTTP 状态码
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