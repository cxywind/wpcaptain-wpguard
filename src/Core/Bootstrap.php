<?php
/**
 * 插件启动核心
 *
 * @package WpGuard
 * @subpackage Core
 */

namespace WpGuard\Core;

/**
 * Class Bootstrap
 *
 * 负责插件的初始化：加载文本域、注册模块、激活/停用挂钩等。
 * 防护引擎在构造函数中提早初始化，以确保其钩子能被 WordPress 正常执行。
 */
class Bootstrap {
    use Singleton;

    /**
     * 构造函数
     *
     * 注册插件生命周期钩子和初始化动作。
     * Protection_Engine 必须在此处初始化，而不是在 plugins_loaded 回调中，
     * 否则其 run_checks 方法将错过钩子执行。
     */
    private function __construct() {
        // 尽早初始化防护引擎，注册 plugins_loaded 钩子
        \WpGuard\Protection\Protection_Engine::init();

        add_action( 'plugins_loaded', [ $this, 'load_textdomain' ] );
        add_action( 'plugins_loaded', [ $this, 'init_modules' ], 5 );
        add_action( 'plugins_loaded', [ $this, 'check_upgrade' ], 10 );
        register_activation_hook( WPGUARD_PATH . 'wpguard.php', [ $this, 'activate' ] );
        register_deactivation_hook( WPGUARD_PATH . 'wpguard.php', [ $this, 'deactivate' ] );
    }

    /**
     * 加载插件翻译文件
     */
    public function load_textdomain() {
        load_plugin_textdomain( 'wpguard', false, dirname( plugin_basename( WPGUARD_PATH ) ) . '/languages' );
    }

    /**
     * 初始化所有功能模块
     *
     * 注意：防护引擎已在构造函数中初始化，这里不再调用。
     */
    public function init_modules() {
        \WpGuard\Cache\Cache_Handler::init();           // 缓存处理器
        \WpGuard\Compatibility\Multisite::init();       // 多站点兼容

        if ( is_admin() ) {
            \WpGuard\Admin\Settings::init();            // 后台设置页面
        }

        \WpGuard\Logger\Log_Handler::init();            // 日志处理器

        // 每日日志清理定时任务
        add_action( 'wpguard_daily_cleanup', [ '\WpGuard\Logger\Log_Handler', 'cleanup_logs' ] );
        if ( ! wp_next_scheduled( 'wpguard_daily_cleanup' ) ) {
            wp_schedule_event( time(), 'daily', 'wpguard_daily_cleanup' );
        }
    }

    /**
     * 检查插件升级，执行必要的数据库迁移
     */
        public function check_upgrade() {
        $stored_version = get_option( 'wpguard_version', '1.0.0' );

        if ( version_compare( $stored_version, '1.1.0', '<' ) ) {
            // 升级到 1.1.0：确保日志表含有新字段
            \WpGuard\Logger\Log_Handler::create_table();

            // 设置默认的指纹检测选项
                        $fingerprint_defaults = [
                'enabled'       => 0,
                'block_level'   => 'strict',
                'custom_groups' => [ 'ua', 'path', 'header' ],
                'features'      => [
                    'c2' => 1, 'c3' => 0,
                    'p1' => 0, 'p2' => 0,
                    'h1' => 0, 'h2' => 0, 'h3' => 0, 'h4' => 0,
                    'r1' => 0, 'r2' => 0, 'r3' => 0, 'r4' => 0,
                    'b1' => 0, 'b2' => 0,
                ],
                'rate_limits'   => [ 'r1' => 300, 'r2' => 30, 'r3' => 50, 'r4' => 20 ],
                'block_action'  => 'error',
                'http_code'     => 403,
                'whitelist_ips' => '',
                'log_only'      => 0,
                'enable_cache'  => 0,
            ];
            add_option( 'wpguard_fingerprint', $fingerprint_defaults );
        }

        // 更新存储的版本号
        if ( version_compare( $stored_version, WPGUARD_VERSION, '<' ) ) {
            update_option( 'wpguard_version', WPGUARD_VERSION );
        }
    }

    /**
     * 插件激活时的回调
     *
     * 创建日志表，如果为网络激活则设置网络默认选项。
     */
    public function activate() {
        \WpGuard\Logger\Log_Handler::create_table();
        if ( is_multisite() && is_plugin_active_for_network( plugin_basename( WPGUARD_PATH . 'wpguard.php' ) ) ) {
            \WpGuard\Compatibility\Multisite::set_network_defaults();
        }
        // 记录插件版本
        add_option( 'wpguard_version', WPGUARD_VERSION );
    }

    /**
     * 插件停用时的回调
     *
     * 清除计划任务。
     */
    public function deactivate() {
        wp_clear_scheduled_hook( 'wpguard_daily_cleanup' );
    }
}
