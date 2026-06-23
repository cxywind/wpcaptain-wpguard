<?php
/**
 * 插件卸载清理
 *
 * 当在后台删除插件时，WordPress 会自动加载此文件。
 * 我们在此处删除所有插件相关的数据表、选项和定时任务。
 *
 * @package WpGuard
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

global $wpdb;

// 删除日志表
$table_name = $wpdb->prefix . 'wpguard_logs';
$wpdb->query( "DROP TABLE IF EXISTS $table_name" );

// 删除所有选项（单站点和多站点）
$option_keys = [ 'basic_filter', 'path_protect', 'whitelist_logs' ];
foreach ( $option_keys as $key ) {
    delete_option( 'wpguard_' . $key );
    delete_option( 'wpguard_' . $key . '_custom' );
}
if ( is_multisite() ) {
    foreach ( $option_keys as $key ) {
        delete_site_option( 'wpguard_' . $key );
    }
}

// 清除定时任务
wp_clear_scheduled_hook( 'wpguard_daily_cleanup' );