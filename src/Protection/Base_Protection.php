<?php
/**
 * 防护模块抽象基类
 *
 * @package WpGuard
 * @subpackage Protection
 */

namespace WpGuard\Protection;

/**
 * Class Base_Protection
 *
 * 所有具体防护类必须继承此类并实现 check() 方法。
 */
abstract class Base_Protection {
    /**
     * 执行防护检查
     *
     * @return bool 返回 true 表示需要拦截该请求
     */
    abstract public function check();
}