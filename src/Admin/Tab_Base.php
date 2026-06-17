<?php
namespace WpGuard\Admin;

/**
 * Abstract class Tab_Base
 * Base for admin settings tabs.
 */
abstract class Tab_Base {
    /**
     * Tab slug.
     *
     * @var string
     */
    protected $slug;

    /**
     * Tab title.
     *
     * @var string
     */
    protected $title;

    /**
     * Option group key.
     *
     * @var string
     */
    protected $option_key;

    /**
     * Default settings.
     *
     * @var array
     */
    protected $defaults = [];

    /**
     * Render the tab content.
     */
    abstract public function render();

    /**
     * Get current settings.
     *
     * @return array
     */
    protected function get_settings() {
        return \WpGuard\Utils\Helpers::get_settings( $this->option_key, $this->defaults );
    }

    /**
     * Save settings.
     *
     * @param array $input Submitted data.
     */
    public function save( $input ) {
        $sanitized = $this->sanitize( $input );
        \WpGuard\Utils\Helpers::update_settings( $this->option_key, $sanitized );
    }

    /**
     * Sanitize settings data. Override in child classes.
     *
     * @param array $input Raw input.
     * @return array
     */
    protected function sanitize( $input ) {
        return array_map( 'sanitize_text_field', $input );
    }

    /**
     * Get tab slug.
     *
     * @return string
     */
    public function get_slug() {
        return $this->slug;
    }

    /**
     * Get tab title.
     *
     * @return string
     */
    public function get_title() {
        return $this->title;
    }
}