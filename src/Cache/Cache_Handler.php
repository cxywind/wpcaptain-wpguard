<?php
namespace WpGuard\Cache;

/**
 * Class Cache_Handler
 * Unified interface for caching. Uses object cache if available, else transients.
 */
class Cache_Handler {
    /**
     * Whether external object cache is available.
     *
     * @var bool
     */
    private static $use_object_cache = false;

    /**
     * Init.
     */
    public static function init() {
        self::$use_object_cache = wp_using_ext_object_cache();
    }

    /**
     * Get a cache value.
     *
     * @param string $key Cache key.
     * @param mixed  $default Default.
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
     * Set a cache value.
     *
     * @param string $key    Cache key.
     * @param mixed  $value  Value.
     * @param int    $expire Expiration in seconds.
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
     * Increment a numeric cache value.
     *
     * @param string $key    Cache key.
     * @param int    $offset Increment amount.
     * @param int    $expire Expiration for new keys.
     * @return int|false New value or false on failure.
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
     * Delete a cache key.
     *
     * @param string $key Cache key.
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