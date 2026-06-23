<?php
/**
 * 多站点兼容处理
 *
 * @package WpGuard
 * @subpackage Compatibility
 */

namespace WpGuard\Compatibility;

/**
 * Class Multisite
 *
 * 管理多站点网络激活时的选项继承与覆盖逻辑。
 * - 网络管理后台：直接读写网络站点选项（wp_sitemeta）
 * - 子站点后台/前台：优先使用子站点自身选项（wp_options），若无则回退到网络选项
 */
class Multisite {
    /**
     * 网络激活状态缓存
     *
     * @var bool|null
     */
    private static $is_network_active = null;

    /**
     * 初始化（目前无需额外操作）
     */
    public static function init() {}

    /**
     * 检查插件是否在网络中激活
     *
     * @return bool
     */
    public static function is_network_activated() {
        if ( is_null( self::$is_network_active ) ) {
            if ( ! is_multisite() ) {
                self::$is_network_active = false;
            } else {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
                self::$is_network_active = is_plugin_active_for_network( plugin_basename( WPGUARD_PATH . 'wpguard.php' ) );
            }
        }
        return self::$is_network_active;
    }

    /**
     * 获取选项值（自动处理多站点上下文）
     *
     * @param string $key     选项键名（不含前缀）
     * @param mixed  $default 默认值
     * @return mixed
     */
    public static function get_option( $key, $default = [] ) {
        $option_name = 'wpguard_' . $key;

        // 网络激活时
        if ( self::is_network_activated() ) {
            // 网络管理后台：直接返回网络级设置
            if ( is_network_admin() ) {
                return get_site_option( $option_name, $default );
            }
            // 子站点（前台或后台）：优先使用子站点自己的设置
            $local = get_option( $option_name, null );
            if ( ! is_null( $local ) ) {
                return $local;
            }
            // 子站点无自定义时，继承网络默认值
            return get_site_option( $option_name, $default );
        }

        // 非多站点：直接返回站点选项
        return get_option( $option_name, $default );
    }

    /**
     * 更新选项值（自动判断当前上下文）
     *
     * @param string $key   选项键名（不含前缀）
     * @param mixed  $value 新值
     */
    public static function update_option( $key, $value ) {
        $option_name = 'wpguard_' . $key;

        if ( self::is_network_activated() && is_network_admin() ) {
            // 网络管理员保存：写入网络站点选项
            update_site_option( $option_name, $value );
        } else {
            // 子站点或单站点保存：写入当前站点选项
            update_option( $option_name, $value );
        }
    }

    /**
     * 删除子站点自定义选项，恢复继承网络默认值
     *
     * @param string $key 选项键名
     */
    public static function delete_option( $key ) {
        $option_name = 'wpguard_' . $key;
        delete_option( $option_name );
    }

    /**
     * 设置网络级别的默认选项（插件网络激活时调用）
     */
    public static function set_network_defaults() {
        update_site_option( 'wpguard_basic_filter', [
            'enable_empty_ua'      => 1,
            'enable_fake_crawler'  => 1,
            'enable_header_check'  => 1,
            'enable_referer_check' => 0,
        ] );
        update_site_option( 'wpguard_path_protect', [
            'enable_sensitive_files' => 1,
            'enable_backup_files'    => 1,
            'allowed_download_dirs'  => '',
            'enable_custom_keywords' => 0,
            'custom_keywords'        => '',
        ] );
    }
}