<?php
/**
 * 插件主入口文件
 *
 * @package WpGuard
 * @since 1.0.0
 *
 * Plugin Name: WpGuard - 智能防护系统
 * Plugin URI:  https://www.wpcaptain.cn/
 * Description: 通过智能过滤、行为分析和 SEO 安全默认值保护 WordPress 免受 CC/DDoS 攻击。
 * Version:     1.1.0
 * Author:      大禹
 * Author URI:  https://www.web-sun.cn
 * License:     GPL-2.0+
 * Text Domain: wpguard
 * Domain Path: /languages
 *
 * WpGuard 是自由软件：您可以自由分发和/或修改
 * 它受 GNU 通用公共许可证的约束，该许可证由自由软件基金会发布，
 * 版本 2 或（根据您的选择）任何后续版本。
 *
 * WpGuard 的分发是希望它有用，但不提供任何担保。
 */

// 防止直接访问
if ( ! defined( 'WPINC' ) ) {
    die;
}

/**
 * 当前插件版本号
 */
define( 'WPGUARD_VERSION', '1.1.0' );

/**
 * 插件根目录路径（带结尾斜杠）
 */
define( 'WPGUARD_PATH', plugin_dir_path( __FILE__ ) );

/**
 * 插件根目录 URL（带结尾斜杠）
 */
define( 'WPGUARD_URL', plugin_dir_url( __FILE__ ) );

/**
 * 最低需要的 PHP 版本
 */
define( 'WPGUARD_MIN_PHP', '7.2' );

// 检查 PHP 版本是否满足最低要求
if ( version_compare( PHP_VERSION, WPGUARD_MIN_PHP, '<' ) ) {
    add_action( 'admin_notices', 'wpguard_php_version_notice' );
    /**
     * 显示 PHP 版本过低的提示
     */
    function wpguard_php_version_notice() {
        ?>
        <div class="notice notice-error">
            <p><?php echo esc_html( sprintf( __( 'WpGuard 需要 PHP 版本 %s 或更高。您当前的版本为 %s。', 'wpguard' ), WPGUARD_MIN_PHP, PHP_VERSION ) ); ?></p>
        </div>
        <?php
    }
    return;
}

// ---------------------------------------------------------------------
// 手动类加载（顺序很重要：必须先加载依赖项）
// ---------------------------------------------------------------------

// 核心基础
require_once WPGUARD_PATH . 'src/Core/Singleton.php';
require_once WPGUARD_PATH . 'src/Core/Bootstrap.php';

// 兼容性与缓存
require_once WPGUARD_PATH . 'src/Compatibility/Multisite.php';
require_once WPGUARD_PATH . 'src/Cache/Cache_Handler.php';

// 日志系统
require_once WPGUARD_PATH . 'src/Logger/Log_Handler.php';

// 爬虫白名单验证（Basic_Filter 会用到）
require_once WPGUARD_PATH . 'src/Whitelist/Crawler_Whitelist.php';

// 工具类
require_once WPGUARD_PATH . 'src/Utils/Helpers.php';
require_once WPGUARD_PATH . 'src/Utils/IP_Utils.php';

// Googlebot 验证器（Fingerprint_Detection 依赖）
require_once WPGUARD_PATH . 'src/Utils/Googlebot_Verifier.php';

// 后台选项卡（依赖 Tab_Base）
require_once WPGUARD_PATH . 'src/Admin/Tab_Base.php';
require_once WPGUARD_PATH . 'src/Admin/Tab_BasicFilter.php';
require_once WPGUARD_PATH . 'src/Admin/Tab_PathProtect.php';
require_once WPGUARD_PATH . 'src/Admin/Tab_WhitelistLogs.php';
require_once WPGUARD_PATH . 'src/Admin/Tab_Fingerprint.php';
require_once WPGUARD_PATH . 'src/Admin/Settings.php';

// 防护模块 —— 抽象父类必须在子类之前加载
require_once WPGUARD_PATH . 'src/Protection/Base_Protection.php';
require_once WPGUARD_PATH . 'src/Protection/Basic_Filter.php';
require_once WPGUARD_PATH . 'src/Protection/Path_Protect.php';
require_once WPGUARD_PATH . 'src/Protection/Fingerprint_Detection.php';
require_once WPGUARD_PATH . 'src/Protection/Protection_Engine.php';

// ---------------------------------------------------------------------
// 启动插件
// ---------------------------------------------------------------------
\WpGuard\Core\Bootstrap::instance();