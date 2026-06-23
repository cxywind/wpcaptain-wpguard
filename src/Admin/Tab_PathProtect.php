<?php
/**
 * “路径保护”设置选项卡
 *
 * @package WpGuard
 * @subpackage Admin
 */

namespace WpGuard\Admin;

/**
 * Class Tab_PathProtect
 */
class Tab_PathProtect extends Tab_Base {
    /**
     * 构造函数
     */
    public function __construct() {
        $this->slug       = 'path_protect';
        $this->title      = __( '路径保护', 'wpguard' );
        $this->option_key = 'path_protect';
        $this->defaults   = [
            'enable_sensitive_files' => 1,
            'enable_backup_files'    => 1,
            'allowed_download_dirs'  => '',
            'enable_custom_keywords' => 0,
            'custom_keywords'        => '',
        ];
    }

    /**
     * 渲染选项卡 HTML
     */
    public function render() {
        $settings = $this->get_settings();
        // 表单提交到当前页面
        ?>
        <form method="post" action="">
            <?php wp_nonce_field( 'wpguard_save_' . $this->slug, 'wpguard_nonce' ); ?>
            <input type="hidden" name="action" value="wpguard_save_settings">
            <input type="hidden" name="tab" value="<?php echo esc_attr( $this->slug ); ?>">
            <table class="form-table">
                <!-- 敏感文件拦截 -->
                <tr>
                    <th scope="row"><?php esc_html_e( '敏感文件', 'wpguard' ); ?> <span class="risk-none"><?php esc_html_e( '无风险', 'wpguard' ); ?></span></th>
                    <td>
                        <label><input type="checkbox" name="settings[enable_sensitive_files]" value="1" <?php checked( 1, $settings['enable_sensitive_files'] ); ?>> <?php esc_html_e( '拦截对 .git、.env、wp-config.php、debug.log 等敏感路径的访问。', 'wpguard' ); ?></label>
                    </td>
                </tr>
                <!-- 备份文件拦截 -->
                <tr>
                    <th scope="row"><?php esc_html_e( '备份/归档文件', 'wpguard' ); ?> <span class="risk-none"><?php esc_html_e( '无风险', 'wpguard' ); ?></span></th>
                    <td>
                        <label><input type="checkbox" name="settings[enable_backup_files]" value="1" <?php checked( 1, $settings['enable_backup_files'] ); ?>> <?php esc_html_e( '禁止直接访问 .zip、.sql、.tar.gz 等备份和归档文件。', 'wpguard' ); ?></label>
                    </td>
                </tr>
                <!-- 允许下载的目录 -->
                <tr>
                    <th scope="row"><?php esc_html_e( '允许下载目录', 'wpguard' ); ?></th>
                    <td>
                        <textarea name="settings[allowed_download_dirs]" rows="3" class="large-text code"><?php echo esc_textarea( $settings['allowed_download_dirs'] ); ?></textarea>
                        <p class="description"><?php esc_html_e( '每行输入一个目录路径（如 /wp-content/uploads/downloads/）。位于这些目录中的文件将不会被拦截。', 'wpguard' ); ?></p>
                    </td>
                </tr>
                <!-- 自定义关键词黑名单 -->
                <tr>
                    <th scope="row"><?php esc_html_e( '自定义关键词', 'wpguard' ); ?> <span class="risk-low"><?php esc_html_e( '低风险', 'wpguard' ); ?></span></th>
                    <td>
                        <label><input type="checkbox" name="settings[enable_custom_keywords]" value="1" <?php checked( 1, $settings['enable_custom_keywords'] ); ?>> <?php esc_html_e( '启用自定义关键词过滤。', 'wpguard' ); ?></label>
                        <br>
                        <textarea name="settings[custom_keywords]" rows="4" class="large-text code"><?php echo esc_textarea( $settings['custom_keywords'] ); ?></textarea>
                        <p class="description"><?php esc_html_e( '每行输入一个关键词，包含该词的请求将被拦截。请谨慎添加，过于宽泛的词可能导致正常功能异常。', 'wpguard' ); ?></p>
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
            'enable_sensitive_files' => ! empty( $input['enable_sensitive_files'] ) ? 1 : 0,
            'enable_backup_files'    => ! empty( $input['enable_backup_files'] ) ? 1 : 0,
            'allowed_download_dirs'  => sanitize_textarea_field( $input['allowed_download_dirs'] ?? '' ),
            'enable_custom_keywords' => ! empty( $input['enable_custom_keywords'] ) ? 1 : 0,
            'custom_keywords'        => sanitize_textarea_field( $input['custom_keywords'] ?? '' ),
        ];
    }
}