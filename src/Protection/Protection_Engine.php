<?php
/**
 * 防护引擎调度中心
 *
 * 加载所有防护模块，并在 WordPress 早期钩子上依次执行检查。
 *
 * @package WpGuard
 * @subpackage Protection
 */

namespace WpGuard\Protection;

/**
 * Class Protection_Engine
 */
class Protection_Engine {
    /**
     * 防护模块实例数组
     *
     * @var Base_Protection[]
     */
    private static $modules = [];

    /**
     * 初始化引擎
     */
    public static function init() {
        self::$modules[] = new Basic_Filter();
        self::$modules[] = new Path_Protect();
        add_action( 'plugins_loaded', [ __CLASS__, 'run_checks' ], 0 );
    }

    /**
     * 依次运行所有防护检查
     *
     * 跳过后台、WP-CLI 和 cron 请求。
     */
    public static function run_checks() {
        // 不拦截管理后台、命令行或计划任务
        if ( is_admin() || defined( 'WP_CLI' ) || defined( 'DOING_CRON' ) ) {
            return;
        }

        foreach ( self::$modules as $module ) {
            if ( $module->check() ) {
                // 模块内部已经执行了拦截并终止
                exit;
            }
        }
    }
}