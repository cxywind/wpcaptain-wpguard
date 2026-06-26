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
            'enable_empty_ua'       => 1,
            'enable_googlebot_check' => 0,
            'enable_cache'          => 0,
        ] );
    }

    /**
     * 执行全部基础过滤检查
     *
     * @return bool
     */
    public function check() {
        // 后台请求放行（由 Fingerprint_Detection 处理未登录后台）
        if ( is_admin() ) {
            return false;
        }

        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // 1. 空 UA 检测
        if ( $this->settings['enable_empty_ua'] && $this->is_empty_ua( $ua ) ) {
            $this->block( '空 User-Agent' );
            return true;
        }

        // 2. Googlebot 真实性验证
        if ( $this->settings['enable_googlebot_check'] && $this->is_fake_googlebot() ) {
            $this->block( '伪造 Googlebot' );
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
     * 检测是否为伪造 Googlebot
     *
     * 通过反向 DNS + 正向 DNS 双重验证。
     * 仅验证 UA 中包含 "Googlebot" 的请求。
     *
     * @return bool true=伪造Googlebot，false=真实Googlebot或非Googlebot
     */
    private function is_fake_googlebot() {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // 不是 Googlebot 则直接放行
        if ( stripos( $ua, 'Googlebot' ) === false ) {
            return false;
        }

        $ip = \WpGuard\Utils\IP_Utils::get_ip();

        // 验证失败即为伪造
        $use_cache = ! empty( $this->settings['enable_cache'] );
        return ! \WpGuard\Utils\Googlebot_Verifier::is_googlebot( $ip, $ua, $use_cache );
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

        // 在 die() 前提交日志队列，确保日志写入数据库
        \WpGuard\Logger\Log_Handler::commit_queue();

        status_header( $code );
        die( 'Access denied.' );
    }
}

