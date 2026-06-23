<?php
/**
 * 单例 trait
 *
 * @package WpGuard
 * @subpackage Core
 */

namespace WpGuard\Core;

/**
 * Trait Singleton
 *
 * 使任何使用该 trait 的类成为单例。
 * 通过静态方法 instance() 获取唯一实例。
 */
trait Singleton {
    /**
     * 单例实例存储
     *
     * @var static|null
     */
    private static $instance = null;

    /**
     * 获取单例实例
     *
     * @return static
     */
    public static function instance() {
        if ( is_null( self::$instance ) ) {
            self::$instance = new self();
        }
        return self::$instance;
    }
}