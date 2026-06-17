<?php
namespace WpGuard\Admin;

/**
 * Class Tab_PathProtect
 * Settings for path and file protection.
 */
class Tab_PathProtect extends Tab_Base {
    /**
     * Constructor.
     */
    public function __construct() {
        $this->slug       = 'path_protect';
        $this->title      = __( 'Path Protection', 'wpguard' );
        $this->option_key = 'path_protect';
        $this->defaults   = [
            'enable_sensitive_files'  => 1,
            'enable_backup_files'     => 1,
            'allowed_download_dirs'   => '',
            'enable_custom_keywords'  => 0,
            'custom_keywords'         => '',
        ];
    }

    /**
     * Render tab content.
     */
    public function render() {
        $settings = $this->get_settings();
        ?>
        <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
            <?php wp_nonce_field( 'wpguard_save_' . $this->slug, 'wpguard_nonce' ); ?>
            <input type="hidden" name="action" value="wpguard_save_settings">
            <input type="hidden" name="tab" value="<?php echo esc_attr( $this->slug ); ?>">
            <table class="form-table">
                <tr>
                    <th scope="row"><?php esc_html_e( 'Sensitive Files', 'wpguard' ); ?> <span class="risk-none"><?php esc_html_e( 'No risk', 'wpguard' ); ?></span></th>
                    <td>
                        <label><input type="checkbox" name="settings[enable_sensitive_files]" value="1" <?php checked( 1, $settings['enable_sensitive_files'] ); ?>> <?php esc_html_e( 'Block access to .git, .env, wp-config.php, debug.log and similar sensitive paths.', 'wpguard' ); ?></label>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Backup / Archive Files', 'wpguard' ); ?> <span class="risk-none"><?php esc_html_e( 'No risk', 'wpguard' ); ?></span></th>
                    <td>
                        <label><input type="checkbox" name="settings[enable_backup_files]" value="1" <?php checked( 1, $settings['enable_backup_files'] ); ?>> <?php esc_html_e( 'Block direct access to .zip, .sql, .tar.gz and other backup/archive files.', 'wpguard' ); ?></label>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Allowed Download Directories', 'wpguard' ); ?></th>
                    <td>
                        <textarea name="settings[allowed_download_dirs]" rows="3" class="large-text code"><?php echo esc_textarea( $settings['allowed_download_dirs'] ); ?></textarea>
                        <p class="description"><?php esc_html_e( 'Enter one directory path per line (e.g., /wp-content/uploads/downloads/). Files in these directories will not be blocked.', 'wpguard' ); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Custom Keywords', 'wpguard' ); ?> <span class="risk-low"><?php esc_html_e( 'Low risk', 'wpguard' ); ?></span></th>
                    <td>
                        <label><input type="checkbox" name="settings[enable_custom_keywords]" value="1" <?php checked( 1, $settings['enable_custom_keywords'] ); ?>> <?php esc_html_e( 'Enable custom keyword filtering.', 'wpguard' ); ?></label>
                        <br>
                        <textarea name="settings[custom_keywords]" rows="4" class="large-text code"><?php echo esc_textarea( $settings['custom_keywords'] ); ?></textarea>
                        <p class="description"><?php esc_html_e( 'Enter keywords (one per line) to block requests containing them. Be careful: overly generic words can break your site.', 'wpguard' ); ?></p>
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }

    /**
     * Sanitize settings.
     *
     * @param array $input Raw input.
     * @return array
     */
    protected function sanitize( $input ) {
        return [
            'enable_sensitive_files'  => ! empty( $input['enable_sensitive_files'] ) ? 1 : 0,
            'enable_backup_files'     => ! empty( $input['enable_backup_files'] ) ? 1 : 0,
            'allowed_download_dirs'   => sanitize_textarea_field( $input['allowed_download_dirs'] ?? '' ),
            'enable_custom_keywords'  => ! empty( $input['enable_custom_keywords'] ) ? 1 : 0,
            'custom_keywords'         => sanitize_textarea_field( $input['custom_keywords'] ?? '' ),
        ];
    }
}