<?php
/**
 * 通用辅助函数
 *
 * @package WpGuard
 * @subpackage Utils
 */

namespace WpGuard\Utils;

/**
 * Class Helpers
 */
class Helpers {
    /**
     * 获取插件设置（自动处理多站点继承）
     *
     * @param string $key     设置组键名
     * @param mixed  $default 默认值
     * @return array
     */
    public static function get_settings( $key, $default = [] ) {
        return \WpGuard\Compatibility\Multisite::get_option( $key, $default );
    }

    /**
     * 更新插件设置
     *
     * @param string $key   设置组键名
     * @param mixed  $value 新值
     */
    public static function update_settings( $key, $value ) {
        \WpGuard\Compatibility\Multisite::update_option( $key, $value );
    }

    /**
     * 获取指定功能的风险等级
     *
     * @param string $feature 功能标识
     * @return string 'none', 'low', 'medium', 'high'
     */
    public static function get_risk_level( $feature ) {
        $risks = [
            'empty_ua'          => 'low',
            'fake_crawler'      => 'none',
            'header_check'      => 'low',
            'referer_check'     => 'low',
            'sensitive_files'   => 'none',
            'backup_files'      => 'none',
            'custom_keywords'   => 'low',
        ];
        return isset( $risks[ $feature ] ) ? $risks[ $feature ] : 'low';
    }
}