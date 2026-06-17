<?php
namespace WpGuard\Admin;

/**
 * Class Tab_BasicFilter
 * Settings for basic request filtering.
 */
class Tab_BasicFilter extends Tab_Base {
    /**
     * Constructor.
     */
    public function __construct() {
        $this->slug       = 'basic_filter';
        $this->title      = __( 'Basic Filter', 'wpguard' );
        $this->option_key = 'basic_filter';
        $this->defaults   = [
            'enable_empty_ua'      => 1,
            'enable_fake_crawler'  => 1,
            'enable_header_check'  => 1,
            'enable_referer_check' => 0,
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
                    <th scope="row"><?php esc_html_e( 'Empty User-Agent', 'wpguard' ); ?> <span class="risk-low"><?php esc_html_e( 'Low risk', 'wpguard' ); ?></span></th>
                    <td>
                        <label><input type="checkbox" name="settings[enable_empty_ua]" value="1" <?php checked( 1, $settings['enable_empty_ua'] ); ?>> <?php esc_html_e( 'Block requests with empty or very short User-Agent.', 'wpguard' ); ?></label>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Fake Search Crawlers', 'wpguard' ); ?> <span class="risk-none"><?php esc_html_e( 'No risk', 'wpguard' ); ?></span></th>
                    <td>
                        <label><input type="checkbox" name="settings[enable_fake_crawler]" value="1" <?php checked( 1, $settings['enable_fake_crawler'] ); ?>> <?php esc_html_e( 'Verify search engine bots (Google, Bing, etc.) via reverse DNS. Blocks impersonators.', 'wpguard' ); ?></label>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Missing Browser Headers', 'wpguard' ); ?> <span class="risk-low"><?php esc_html_e( 'Low risk', 'wpguard' ); ?></span></th>
                    <td>
                        <label><input type="checkbox" name="settings[enable_header_check]" value="1" <?php checked( 1, $settings['enable_header_check'] ); ?>> <?php esc_html_e( 'Block requests missing standard headers (Accept-Language, Accept-Encoding).', 'wpguard' ); ?></label>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Referer Protection', 'wpguard' ); ?> <span class="risk-low"><?php esc_html_e( 'Low risk', 'wpguard' ); ?></span></th>
                    <td>
                        <label><input type="checkbox" name="settings[enable_referer_check]" value="1" <?php checked( 1, $settings['enable_referer_check'] ); ?>> <?php esc_html_e( 'Block direct access to login/admin pages without a proper referrer.', 'wpguard' ); ?></label>
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
            'enable_empty_ua'      => ! empty( $input['enable_empty_ua'] ) ? 1 : 0,
            'enable_fake_crawler'  => ! empty( $input['enable_fake_crawler'] ) ? 1 : 0,
            'enable_header_check'  => ! empty( $input['enable_header_check'] ) ? 1 : 0,
            'enable_referer_check' => ! empty( $input['enable_referer_check'] ) ? 1 : 0,
        ];
    }
}