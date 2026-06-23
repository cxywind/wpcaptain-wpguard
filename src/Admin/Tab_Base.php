<?php
/**
 * 后台设置选项卡基类
 *
 * @package WpGuard
 * @subpackage Admin
 */

namespace WpGuard\Admin;

/**
 * Abstract class Tab_Base
 *
 * 所有具体选项卡都必须继承此类，并实现 render() 方法。
 */
abstract class Tab_Base {
    /**
     * 选项卡标识（用于 URL 参数）
     *
     * @var string
     */
    protected $slug;

    /**
     * 选项卡标题
     *
     * @var string
     */
    protected $title;

    /**
     * 对应的设置选项键名（不含前缀）
     *
     * @var string
     */
    protected $option_key;

    /**
     * 默认设置值
     *
     * @var array
     */
    protected $defaults = [];

    /**
     * 渲染选项卡内容
     */
    abstract public function render();

    /**
     * 获取当前设置值（考虑多站点继承）
     *
     * @return array
     */
    protected function get_settings() {
        return \WpGuard\Utils\Helpers::get_settings( $this->option_key, $this->defaults );
    }

    /**
     * 保存设置
     *
     * @param array $input 用户提交的数据
     */
    public function save( $input ) {
        $sanitized = $this->sanitize( $input );
        \WpGuard\Utils\Helpers::update_settings( $this->option_key, $sanitized );
    }

    /**
     * 数据消毒处理
     *
     * 子类可以重写此方法以实现特定字段的消毒逻辑。
     *
     * @param array $input 原始输入
     * @return array
     */
    protected function sanitize( $input ) {
        return array_map( 'sanitize_text_field', $input );
    }

    /**
     * 获取选项卡 slug
     *
     * @return string
     */
    public function get_slug() {
        return $this->slug;
    }

    /**
     * 获取选项卡标题
     *
     * @return string
     */
    public function get_title() {
        return $this->title;
    }
}