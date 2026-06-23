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
            'enable_empty_ua'      => 1,
            'enable_fake_crawler'  => 1,
            'enable_header_check'  => 1,
            'enable_referer_check' => 0,
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
                <!-- 伪造爬虫验证 -->
                <tr>
                    <th scope="row"><?php esc_html_e( '伪造搜索爬虫', 'wpguard' ); ?> <span class="risk-none"><?php esc_html_e( '无风险', 'wpguard' ); ?></span></th>
                    <td>
                        <label><input type="checkbox" name="settings[enable_fake_crawler]" value="1" <?php checked( 1, $settings['enable_fake_crawler'] ); ?>> <?php esc_html_e( '通过反向 DNS 验证 Google、Bing 等爬虫。拦截冒充者。', 'wpguard' ); ?></label>
                    </td>
                </tr>
                <!-- 缺失标准请求头 -->
                <tr>
                    <th scope="row"><?php esc_html_e( '缺失浏览器头', 'wpguard' ); ?> <span class="risk-low"><?php esc_html_e( '低风险', 'wpguard' ); ?></span></th>
                    <td>
                        <label><input type="checkbox" name="settings[enable_header_check]" value="1" <?php checked( 1, $settings['enable_header_check'] ); ?>> <?php esc_html_e( '拦截缺少 Accept-Language、Accept-Encoding 等标准头的请求。', 'wpguard' ); ?></label>
                    </td>
                </tr>
                <!-- Referer 保护 -->
                <tr>
                    <th scope="row"><?php esc_html_e( 'Referer 保护', 'wpguard' ); ?> <span class="risk-low"><?php esc_html_e( '低风险', 'wpguard' ); ?></span></th>
                    <td>
                        <label><input type="checkbox" name="settings[enable_referer_check]" value="1" <?php checked( 1, $settings['enable_referer_check'] ); ?>> <?php esc_html_e( '拦截直接访问登录/管理页面且没有本站 Referer 的请求。', 'wpguard' ); ?></label>
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
            'enable_empty_ua'      => ! empty( $input['enable_empty_ua'] ) ? 1 : 0,
            'enable_fake_crawler'  => ! empty( $input['enable_fake_crawler'] ) ? 1 : 0,
            'enable_header_check'  => ! empty( $input['enable_header_check'] ) ? 1 : 0,
            'enable_referer_check' => ! empty( $input['enable_referer_check'] ) ? 1 : 0,
        ];
    }
}