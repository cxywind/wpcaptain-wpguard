<?php
/**
 * “基础过滤”设置选项卡
 *
 * @package WpGuard
 * @subpackage Admin
 */

namespace WpGuard\Admin;

/**
 * Class Tab_BasicFilter
 */
class Tab_BasicFilter extends Tab_Base {
    /**
     * 构造函数：初始化选项卡属性
     */
    public function __construct() {
        $this->slug       = 'basic_filter';
        $this->title      = __( '基础过滤', 'wpguard' );
        $this->option_key = 'basic_filter';
        $this->defaults   = [
            'enable_empty_ua'       => 1,
            'enable_googlebot_check' => 0,
            'enable_cache'          => 0,
        ];
    }

    /**
     * 渲染选项卡 HTML
     */
    public function render() {
        $settings = $this->get_settings();
        // 表单提交到当前页面，不再使用 admin-post.php
        ?>
        <form method="post" action="">
            <?php wp_nonce_field( 'wpguard_save_' . $this->slug, 'wpguard_nonce' ); ?>
            <input type="hidden" name="action" value="wpguard_save_settings">
            <input type="hidden" name="tab" value="<?php echo esc_attr( $this->slug ); ?>">
                        <table class="form-table">
                <!-- 空 UA 拦截 -->
                <tr>
                    <th scope="row"><?php esc_html_e( '空 User-Agent', 'wpguard' ); ?> <span class="risk-low"><?php esc_html_e( '低风险', 'wpguard' ); ?></span></th>
                    <td>
                        <label><input type="checkbox" name="settings[enable_empty_ua]" value="1" <?php checked( 1, $settings['enable_empty_ua'] ); ?>> <?php esc_html_e( '拦截 User-Agent 为空或过短的请求。', 'wpguard' ); ?></label>
                    </td>
                </tr>
                <!-- Googlebot 验证 -->
                <tr>
                    <th scope="row"><?php esc_html_e( 'Googlebot 真实性验证', 'wpguard' ); ?> <span class="risk-none"><?php esc_html_e( '无风险', 'wpguard' ); ?></span></th>
                    <td>
                        <label><input type="checkbox" name="settings[enable_googlebot_check]" value="1" <?php checked( 1, $settings['enable_googlebot_check'] ); ?>> <?php esc_html_e( '通过反向 DNS 验证 Googlebot 真实性，拦截冒充者。仅验证 UA 中包含 "Googlebot" 的请求。', 'wpguard' ); ?></label>
                        <p class="description"><?php esc_html_e( 'Bing、Yandex 等其他爬虫验证请在「指纹检测」中配置。', 'wpguard' ); ?></p>
                    </td>
                </tr>
                <!-- 爬虫验证缓存 -->
                <tr>
                    <th scope="row"><?php esc_html_e( '爬虫验证缓存', 'wpguard' ); ?> <span class="risk-medium"><?php esc_html_e( '中风险', 'wpguard' ); ?></span></th>
                    <td>
                        <label><input type="checkbox" name="settings[enable_cache]" value="1" <?php checked( 1, $settings['enable_cache'] ); ?>> <?php esc_html_e( '启用爬虫验证结果缓存（24小时）。', 'wpguard' ); ?></label>
                        <p class="description" style="color: #d63638;"><?php esc_html_e( '⚠️ 启用缓存后，已验证的爬虫 IP 结果将保存 24 小时。如果该 IP 在此期间被重新分配给恶意请求者，可能造成漏拦。建议仅在网站日均访问量超过 10,000 时开启。', 'wpguard' ); ?></p>
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }

    /**
     * 数据消毒
     *
     * @param array $input 表单提交数据
     * @return array
     */
        protected function sanitize( $input ) {
        return [
            'enable_empty_ua'       => ! empty( $input['enable_empty_ua'] ) ? 1 : 0,
            'enable_googlebot_check' => ! empty( $input['enable_googlebot_check'] ) ? 1 : 0,
            'enable_cache'          => ! empty( $input['enable_cache'] ) ? 1 : 0,
        ];
    }
}