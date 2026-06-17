<?php
namespace WpGuard\Protection;

/**
 * Class Base_Protection
 * Base class for protection modules.
 */
abstract class Base_Protection {
    /**
     * Check if request should be blocked.
     *
     * @return bool True to block.
     */
    abstract public function check();
}