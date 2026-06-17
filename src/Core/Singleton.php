<?php
namespace WpGuard\Core;

/**
 * Trait Singleton
 * Makes a class a singleton.
 */
trait Singleton {
    /**
     * Instance holder.
     *
     * @var static|null
     */
    private static $instance = null;

    /**
     * Get the singleton instance.
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