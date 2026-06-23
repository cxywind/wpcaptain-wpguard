<?php
/**
 * 缓存处理类
 *
 * 提供统一的数据缓存接口。如果服务器安装了 Redis/Memcached 等外部对象缓存，则优先使用；
 * 否则降级为 WordPress 的 Transients API。
 *
 * @package WpGuard
 * @subpackage Cache
 */

namespace WpGuard\Cache;

/**
 * Class Cache_Handler
 */
class Cache_Handler {
    /**
     * 是否可用外部对象缓存
     *
     * @var bool
     */
    private static $use_object_cache = false;

    /**
     * 初始化缓存处理器
     */
    public static function init() {
        self::$use_object_cache = wp_using_ext_object_cache();
    }

    /**
     * 获取一个缓存值
     *
     * @param string $key     缓存键
     * @param mixed  $default 如果不存在，返回的默认值
     * @return mixed
     */
    public static function get( $key, $default = false ) {
        $key = 'wpguard_' . $key;
        if ( self::$use_object_cache ) {
            $value = wp_cache_get( $key, 'wpguard' );
            return false === $value ? $default : $value;
        }
        return get_transient( $key ) ?: $default;
    }

    /**
     * 设置一个缓存值
     *
     * @param string $key    缓存键
     * @param mixed  $value  缓存值
     * @param int    $expire 过期时间（秒）
     */
    public static function set( $key, $value, $expire = 3600 ) {
        $key = 'wpguard_' . $key;
        if ( self::$use_object_cache ) {
            wp_cache_set( $key, $value, 'wpguard', $expire );
        } else {
            set_transient( $key, $value, $expire );
        }
    }

    /**
     * 自增一个数值缓存项
     *
     * @param string $key    缓存键
     * @param int    $offset 增量（默认 1）
     * @param int    $expire 过期时间（新键时使用）
     * @return int|false 自增后的值，失败返回 false
     */
    public static function incr( $key, $offset = 1, $expire = 3600 ) {
        $key = 'wpguard_' . $key;
        if ( self::$use_object_cache ) {
            $current = wp_cache_get( $key, 'wpguard' );
            if ( false === $current ) {
                $current = 0;
                wp_cache_set( $key, $current, 'wpguard', $expire );
            }
            $new_val = $current + $offset;
            wp_cache_set( $key, $new_val, 'wpguard', $expire );
            return $new_val;
        }
        $current = get_transient( $key );
        if ( false === $current ) {
            $current = 0;
            set_transient( $key, $current, $expire );
        }
        $new_val = $current + $offset;
        set_transient( $key, $new_val, $expire );
        return $new_val;
    }

    /**
     * 删除一个缓存项
     *
     * @param string $key 缓存键
     */
    public static function delete( $key ) {
        $key = 'wpguard_' . $key;
        if ( self::$use_object_cache ) {
            wp_cache_delete( $key, 'wpguard' );
        } else {
            delete_transient( $key );
        }
    }
}