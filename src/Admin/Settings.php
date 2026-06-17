<?php
namespace WpGuard\Admin;

/**
 * Class Settings
 * Main settings page with tab navigation.
 */
class Settings {
    /**
     * Registered tabs.
     *
     * @var Tab_Base[]
     */
    private $tabs = [];

    /**
     * Init hooks.
     */
    public static function init() {
        $self = new self();
        $self->register_tabs();
        add_action( is_multisite() && \WpGuard\Compatibility\Multisite::is_network_activated() ? 'network_admin_menu' : 'admin_menu', [ $self, 'add_menu' ] );
        add_action( 'admin_post_wpguard_save_settings', [ $self, 'save_settings' ] );
    }

    /**
     * Register all available tabs.
     */
    private function register_tabs() {
        $this->tabs[] = new Tab_BasicFilter();
        $this->tabs[] = new Tab_PathProtect();
        $this->tabs[] = new Tab_WhitelistLogs();
    }

    /**
     * Add admin menu page.
     */
    public function add_menu() {
        add_menu_page(
            __( 'WpGuard', 'wpguard' ),
            __( 'WpGuard', 'wpguard' ),
            'manage_options',
            'wpguard',
            [ $this, 'render_page' ],
            'dashicons-shield',
            80
        );
    }

    /**
     * Render settings page with tabs.
     */
    public function render_page() {
        $current_tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : $this->tabs[0]->get_slug();
        ?>
        <div class="wrap">
            <h1><?php esc_html_e( 'WpGuard Settings', 'wpguard' ); ?></h1>
            <nav class="nav-tab-wrapper">
                <?php foreach ( $this->tabs as $tab ) : ?>
                    <a href="?page=wpguard&tab=<?php echo esc_attr( $tab->get_slug() ); ?>"
                       class="nav-tab <?php echo $current_tab === $tab->get_slug() ? 'nav-tab-active' : ''; ?>">
                        <?php echo esc_html( $tab->get_title() ); ?>
                    </a>
                <?php endforeach; ?>
            </nav>
            <div class="tab-content">
                <?php
                foreach ( $this->tabs as $tab ) {
                    if ( $current_tab === $tab->get_slug() ) {
                        $tab->render();
                        break;
                    }
                }
                ?>
            </div>
        </div>
        <?php
    }

    /**
     * Handle settings save.
     */
    public function save_settings() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }
        $tab_slug = isset( $_POST['tab'] ) ? sanitize_key( $_POST['tab'] ) : '';
        check_admin_referer( 'wpguard_save_' . $tab_slug, 'wpguard_nonce' );

        foreach ( $this->tabs as $tab ) {
            if ( $tab->get_slug() === $tab_slug ) {
                $tab->save( $_POST['settings'] ?? [] );
                break;
            }
        }

        $redirect_url = add_query_arg( [ 'page' => 'wpguard', 'tab' => $tab_slug, 'saved' => 'true' ], is_network_admin() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' ) );
        wp_safe_redirect( $redirect_url );
        exit;
    }
}