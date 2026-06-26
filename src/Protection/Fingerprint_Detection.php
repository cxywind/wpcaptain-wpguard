<?php
/**
 * 指纹特征检测引擎
 *
 * 收集多个维度的请求特征（UA、路径、频率、爬虫等），
 * 根据封禁级别（宽松/严格/自定义）综合判断是否拦截。
 *
 * 检测顺序：零IO特征优先 → 轻度IO特征 → 需外部缓存特征。
 * 每个特征检测后立即判断封禁条件，达标即阻断，实现短路优化。
 *
 * @package WpGuard
 * @subpackage Protection
 */

namespace WpGuard\Protection;

use WpGuard\Utils\Googlebot_Verifier;
use WpGuard\Cache\Cache_Handler;
use WpGuard\Utils\IP_Utils;
use WpGuard\Logger\Log_Handler;

/**
 * Class Fingerprint_Detection
 */
class Fingerprint_Detection extends Base_Protection {

    /**
     * 当前设置
     *
     * @var array
     */
    private $settings;

    /**
     * 命中的分组列表（去重）
     *
     * @var array
     */
    private $hit_groups = [];

    /**
     * 命中的特征列表（用于日志）
     *
     * @var array
     */
    private $hit_features = [];

    /**
     * 检测开始时间（用于性能日志）
     *
     * @var float
     */
    private $check_start = 0;

    /**
     * 构造函数：加载设置
     */
    public function __construct() {
        $this->settings = \WpGuard\Utils\Helpers::get_settings( 'fingerprint', [
            'enabled'       => 0,
            'block_level'   => 'strict',
            'custom_groups' => [ 'ua', 'path' ],
            'features'      => [
                'c2' => 1,
                'c3' => 0,
                'p1' => 0,
                'p2' => 0,
                'r1' => 0,
                'r2' => 0,
                'r3' => 0,
                'r4' => 0,
                'b1' => 1,
            ],
            'rate_limits'   => [
                'r1' => 300,
                'r2' => 30,
                'r3' => 50,
                'r4' => 20,
            ],
            'block_action'  => 'error',
            'http_code'     => 403,
            'whitelist_ips' => '',
            'log_only'      => 0,
        ] );
    }

    /**
     * 执行指纹检测
     *
     * @return bool
     */
    public function check() {
        // 模块禁用则放行
        if ( empty( $this->settings['enabled'] ) ) {
            return false;
        }

        // 后台请求放行（让 Basic_Filter 和 Path_Protect 处理）
        if ( is_admin() ) {
            return false;
        }

        $ip = IP_Utils::get_ip();

        // IP 白名单检查
        if ( $this->is_whitelisted( $ip ) ) {
            return false;
        }

        $this->check_start = microtime( true );
        $this->hit_groups  = [];
        $this->hit_features = [];

        // 检测是否启用外部对象缓存（R系列依赖）
        $has_object_cache = wp_using_ext_object_cache();

        // ─── 阶段1：零IO特征（内存操作） ───

        // 1. P1 - 仅扫描脚本文件
        if ( ! empty( $this->settings['features']['p1'] ) ) {
            if ( $this->check_p1( $ip ) ) {
                $this->mark_hit( 'p1', 'path' );
                if ( $this->should_block() ) {
                    $this->block( 'P1-仅扫描脚本' );
                    return true;
                }
            }
        }

        // 2. P2 - 高频敏感路径
        if ( ! empty( $this->settings['features']['p2'] ) ) {
            if ( $this->check_p2( $ip ) ) {
                $this->mark_hit( 'p2', 'path' );
                if ( $this->should_block() ) {
                    $this->block( 'P2-高频敏感路径' );
                    return true;
                }
            }
        }

        // 3. C2 - 老旧浏览器 UA
        if ( ! empty( $this->settings['features']['c2'] ) ) {
            if ( $this->check_c2() ) {
                $this->mark_hit( 'c2', 'ua' );
                if ( $this->should_block() ) {
                    $this->block( 'C2-老旧UA' );
                    return true;
                }
            }
        }

        // ─── 阶段2：轻度IO特征（缓存读写） ───

        // 4. C3 - UA 高频轮换
        if ( ! empty( $this->settings['features']['c3'] ) ) {
            if ( $this->check_c3( $ip ) ) {
                $this->mark_hit( 'c3', 'ua' );
                if ( $this->should_block() ) {
                    $this->block( 'C3-UA轮换' );
                    return true;
                }
            }
        }

        // 5. B1 - 伪造 Googlebot
        if ( ! empty( $this->settings['features']['b1'] ) ) {
            if ( $this->check_b1( $ip ) ) {
                $this->mark_hit( 'b1', 'crawler' );
                if ( $this->should_block() ) {
                    $this->block( 'B1-伪造Googlebot' );
                    return true;
                }
            }
        }

        // ─── 阶段3：需外部缓存特征 ───
        if ( $has_object_cache ) {
            // 6-9. R1-R4 频率特征
            $this->check_rate_features( $ip );
        }

        return false;
    }

    /**
     * P1 - 仅扫描脚本文件检测
     *
     * 记录连续请求脚本文件的次数，达到阈值则触发。
     * 遇到非脚本请求则重置计数器。
     *
     * @param string $ip
     * @return bool
     */
    private function check_p1( $ip ) {
        $uri      = $_SERVER['REQUEST_URI'] ?? '';
        $ext      = strtolower( pathinfo( parse_url( $uri, PHP_URL_PATH ), PATHINFO_EXTENSION ) );
        $is_script = in_array( $ext, [ 'php', 'asp', 'aspx', 'jsp', 'cgi' ], true );

        $cache_key = 'fp_path_' . $ip;
        $data      = Cache_Handler::get( $cache_key, [] );

        $now = time();

        // 重置过期检查（120秒窗口）
        if ( ! empty( $data['p1_time'] ) && ( $now - $data['p1_time'] ) > 120 ) {
            $data['p1_count'] = 0;
        }

        if ( $is_script ) {
            $data['p1_count'] = isset( $data['p1_count'] ) ? $data['p1_count'] + 1 : 1;
        } else {
            $data['p1_count'] = 0;
        }

        $data['p1_time'] = $now;

        Cache_Handler::set( $cache_key, $data, 180 );

        // 连续 5 次及以上脚本请求触发
        return isset( $data['p1_count'] ) && $data['p1_count'] >= 5;
    }

    /**
     * P2 - 高频敏感路径检测
     *
     * 短时间内频繁访问 wp-admin、wp-login.php 等敏感路径。
     *
     * @param string $ip
     * @return bool
     */
    private function check_p2( $ip ) {
        $uri      = $_SERVER['REQUEST_URI'] ?? '';
        $sensitive = false;

        $patterns = [
            '/wp-admin',
            '/wp-login.php',
            '/xmlrpc.php',
            '/wp-json',
            '/wp-content/plugins',
            '/wp-content/themes',
            '/wp-includes',
        ];

        foreach ( $patterns as $pattern ) {
            if ( false !== stripos( $uri, $pattern ) ) {
                $sensitive = true;
                break;
            }
        }

        if ( ! $sensitive ) {
            return false;
        }

        $cache_key = 'fp_path_' . $ip;
        $data      = Cache_Handler::get( $cache_key, [] );

        $now = time();

        // 初始化或过期重置
        if ( empty( $data['p2_time'] ) || ( $now - $data['p2_time'] ) > 60 ) {
            $data['p2_count'] = 0;
            $data['p2_time']  = $now;
        }

        $data['p2_count'] = isset( $data['p2_count'] ) ? $data['p2_count'] + 1 : 1;

        Cache_Handler::set( $cache_key, $data, 120 );

        // 60 秒内超过 20 次触发
        return $data['p2_count'] >= 20;
    }

    /**
     * C2 - 老旧浏览器 UA 检测
     *
     * @return bool
     */
    private function check_c2() {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

        if ( empty( $ua ) ) {
            return false;
        }

        // IE ≤ 8
        if ( preg_match( '/MSIE\s+[0-8]\./i', $ua ) ) {
            return true;
        }
        // IE 6.0
        if ( preg_match( '/MSIE\s+6\.0/i', $ua ) ) {
            return true;
        }

        // Firefox ≤ 3
        if ( preg_match( '/Firefox\/[0-3]\./i', $ua ) ) {
            return true;
        }
        if ( preg_match( '/Firefox\/1\.5/i', $ua ) ) {
            return true;
        }

        // Chrome ≤ 1
        if ( preg_match( '/Chrome\/[0-1]\./i', $ua ) ) {
            return true;
        }
        if ( preg_match( '/Chrome\/0\./i', $ua ) ) {
            return true;
        }

        // Safari ≤ 525 (Version ≤ 4.x)
        if ( preg_match( '/Version\/[0-4]\.[0-9]/', $ua ) && preg_match( '/Safari\/5[0-2][0-9]/', $ua ) ) {
            return true;
        }

        return false;
    }

    /**
     * C3 - UA 高频轮换检测
     *
     * 同一 IP 在 300 秒内使用 3 种以上不同 UA。
     *
     * @param string $ip
     * @return bool
     */
    private function check_c3( $ip ) {
        $ua    = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $ua_hash = sha1( $ua );

        $cache_key = 'fp_ua_' . $ip;
        $data      = Cache_Handler::get( $cache_key, [] );

        $now = time();

        // 初始化或过期重置
        if ( empty( $data['time'] ) || ( $now - $data['time'] ) > 300 ) {
            $data['uas']  = [];
            $data['time'] = $now;
        }

        // 如果当前 UA 不在列表中，追加
        if ( ! in_array( $ua_hash, $data['uas'], true ) ) {
            $data['uas'][] = $ua_hash;
        }

        Cache_Handler::set( $cache_key, $data, 360 );

        // 3 种以上不同 UA 触发
        return count( $data['uas'] ) >= 3;
    }

    /**
     * B1 - 伪造 Googlebot 检测
     *
     * @param string $ip
     * @return bool true 表示伪造 Googlebot
     */
    private function check_b1( $ip ) {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // 不是 Googlebot 则不触发
        if ( stripos( $ua, 'Googlebot' ) === false ) {
            return false;
        }

        // 验证失败即为伪造
        return ! Googlebot_Verifier::is_googlebot( $ip, $ua );
    }

    /**
     * R1-R4 频率特征检测
     *
     * 仅在启用外部对象缓存时执行。
     *
     * @param string $ip
     */
    private function check_rate_features( $ip ) {
        $settings   = $this->settings['features'];
        $rate_limits = $this->settings['rate_limits'];
        $uri         = $_SERVER['REQUEST_URI'] ?? '';
        $method      = $_SERVER['REQUEST_METHOD'] ?? 'GET';

        $cache_key = 'fp_rate_' . $ip;
        $data      = Cache_Handler::get( $cache_key, [] );

        $now = time();

        // 初始化或过期重置（60秒窗口）
        if ( empty( $data['time'] ) || ( $now - $data['time'] ) > 60 ) {
            $data = [
                'total'  => 0,
                'search' => 0,
                'notfound' => 0,
                'write'  => 0,
                'time'   => $now,
            ];
        }

        // R1 - 全局高频：每个请求 +1
        if ( ! empty( $settings['r1'] ) ) {
            $data['total'] = isset( $data['total'] ) ? $data['total'] + 1 : 1;
            if ( $data['total'] >= $rate_limits['r1'] ) {
                $this->mark_hit( 'r1', 'rate' );
                if ( $this->should_block() ) {
                    $this->block( 'R1-全局高频' );
                    return;
                }
            }
        }

        // R2 - 高频搜索：?s= 请求
        if ( ! empty( $settings['r2'] ) && false !== strpos( $uri, '?s=' ) ) {
            $data['search'] = isset( $data['search'] ) ? $data['search'] + 1 : 1;
            if ( $data['search'] >= $rate_limits['r2'] ) {
                $this->mark_hit( 'r2', 'rate' );
                if ( $this->should_block() ) {
                    $this->block( 'R2-高频搜索' );
                    return;
                }
            }
        }

        // R3 - 高频404：在 shutdown 时处理，此处只加标记
        if ( ! empty( $settings['r3'] ) ) {
            // 延迟到 shutdown 判断 is_404()；不传递 data 引用，
            // 改为在 shutdown 时直接从缓存重新读取
            $GLOBALS['wpguard_check_404'][ $ip ] = [
                'cache_key'  => $cache_key,
                'rate_limit' => $rate_limits['r3'],
            ];
            add_action( 'shutdown', [ $this, 'check_r3_on_shutdown' ], 999 );
        }

        // R4 - 高频写操作：POST 到购物车/结账等
        if ( ! empty( $settings['r4'] ) && $method === 'POST' ) {
            $write_patterns = [ '/cart/', '/checkout/', '/add-to-cart', '/wc-api/', '/wp-login.php' ];
            $is_write       = false;
            foreach ( $write_patterns as $pattern ) {
                if ( false !== stripos( $uri, $pattern ) ) {
                    $is_write = true;
                    break;
                }
            }
            if ( $is_write ) {
                $data['write'] = isset( $data['write'] ) ? $data['write'] + 1 : 1;
                if ( $data['write'] >= $rate_limits['r4'] ) {
                    $this->mark_hit( 'r4', 'rate' );
                    if ( $this->should_block() ) {
                        $this->block( 'R4-高频写操作' );
                        Cache_Handler::set( $cache_key, $data, 120 );
                        return;
                    }
                }
            }
        }

        Cache_Handler::set( $cache_key, $data, 120 );
    }

    /**
     * R3 延迟检测：在 shutdown 时判断 is_404()
     *
     * 注：此处不从全局变量读取 data 引用（已废弃），
     * 改为从缓存中重新读取当前计数。
     */
    public function check_r3_on_shutdown() {
        if ( ! is_404() ) {
            return;
        }

        $ip = IP_Utils::get_ip();
        if ( empty( $GLOBALS['wpguard_check_404'][ $ip ] ) ) {
            return;
        }

        $ctx       = $GLOBALS['wpguard_check_404'][ $ip ];
        $cache_key = $ctx['cache_key'];

        // 从缓存重新读取 data
        $data = Cache_Handler::get( $cache_key, [] );

        $data['notfound'] = isset( $data['notfound'] ) ? $data['notfound'] + 1 : 1;

        if ( $data['notfound'] >= $ctx['rate_limit'] ) {
            $this->hit_groups[]   = 'rate';
            $this->hit_features[] = 'r3';
            if ( $this->should_block() ) {
                // 在 shutdown 时先写回缓存，再记录日志并退出
                Cache_Handler::set( $cache_key, $data, 120 );
                Log_Handler::log( [
                    'reason'       => 'R3-高频404',
                    'status_code'  => $this->settings['http_code'],
                    'hit_features' => implode( ',', $this->hit_features ),
                    'perf_ms'      => $this->get_elapsed_ms(),
                ] );
                // 在 die() 前提交日志队列，确保日志写入数据库
                Log_Handler::commit_queue();
                status_header( $this->settings['http_code'] );
                die( 'Access denied.' );
            }
        }

        Cache_Handler::set( $cache_key, $data, 120 );
        unset( $GLOBALS['wpguard_check_404'][ $ip ] );
    }

    /**
     * 标记特征和分组命中
     *
     * @param string $feature 特征标识
     * @param string $group   分组标识
     */
    private function mark_hit( $feature, $group ) {
        $this->hit_features[] = $feature;
        if ( ! in_array( $group, $this->hit_groups, true ) ) {
            $this->hit_groups[] = $group;
        }
    }

    /**
     * 判断当前是否已达到封禁条件
     *
     * @return bool
     */
    private function should_block() {
        $level = $this->settings['block_level'];
        $count = count( $this->hit_groups );

        switch ( $level ) {
            case 'loose':
                return $count >= 2;
            case 'strict':
                return $count >= 3;
            case 'custom':
                $custom_groups = $this->settings['custom_groups'];
                if ( empty( $custom_groups ) ) {
                    return false;
                }
                // 检查所有选中的分组是否都已命中
                $missed = array_diff( $custom_groups, $this->hit_groups );
                return empty( $missed );
            default:
                return false;
        }
    }

    /**
     * 检查 IP 是否在白名单中
     *
     * @param string $ip
     * @return bool
     */
    private function is_whitelisted( $ip ) {
        $whitelist = trim( $this->settings['whitelist_ips'] ?? '' );
        if ( empty( $whitelist ) ) {
            return false;
        }

        $lines = array_filter( array_map( 'trim', explode( "\n", $whitelist ) ) );

        foreach ( $lines as $line ) {
            // 跳过注释和空行
            if ( empty( $line ) || strpos( $line, '#' ) === 0 ) {
                continue;
            }

            // 精确匹配
            if ( $line === $ip ) {
                return true;
            }

            // CIDR 匹配
            if ( strpos( $line, '/' ) !== false ) {
                if ( IP_Utils::ip_in_range( $ip, $line ) ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * 获取检测耗时（毫秒）
     *
     * @return float
     */
    private function get_elapsed_ms() {
        return round( ( microtime( true ) - $this->check_start ) * 1000, 2 );
    }

    /**
     * 执行拦截
     *
     * @param string $reason 拦截原因
     */
    private function block( $reason ) {
        $code = ! empty( $this->settings['http_code'] ) ? (int) $this->settings['http_code'] : 403;

        // 测试模式：仅记录日志，不拦截
        if ( ! empty( $this->settings['log_only'] ) ) {
            Log_Handler::log( [
                'reason'       => '[TEST] ' . $reason,
                'status_code'  => $code,
                'hit_features' => implode( ',', $this->hit_features ),
                'perf_ms'      => $this->get_elapsed_ms(),
            ] );
            return;
        }

        // 正常拦截
        Log_Handler::log( [
            'reason'       => $reason,
            'status_code'  => $code,
            'hit_features' => implode( ',', $this->hit_features ),
            'perf_ms'      => $this->get_elapsed_ms(),
        ] );

        // 在 die() 前提交日志队列，确保日志写入数据库
        Log_Handler::commit_queue();

        status_header( $code );
        die( 'Access denied.' );
    }
}
