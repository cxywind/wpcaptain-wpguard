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
 * 子站点可以自定义设置，未自定义时自动继承网络默认值。
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
     * 获取选项值（考虑多站点继承）
     *
     * @param string $key     选项键名（不含前缀）
     * @param mixed  $default 默认值
     * @return mixed
     */
    public static function get_option( $key, $default = [] ) {
        $option_name = 'wpguard_' . $key;
        if ( self::is_network_activated() ) {
            // 网络模式下，优先使用子站点自定义值
            if ( get_option( $option_name . '_custom' ) ) {
                $value = get_option( $option_name, null );
                if ( ! is_null( $value ) ) {
                    return $value;
                }
            }
            // 否则返回网络默认值
            return get_site_option( $option_name, $default );
        }
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
            update_site_option( $option_name, $value );
        } else {
            // 子站点保存时标记为“自定义”
            update_option( $option_name . '_custom', 1 );
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
        delete_option( $option_name . '_custom' );
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