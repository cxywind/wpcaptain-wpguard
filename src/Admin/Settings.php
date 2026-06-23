<?php
/**
 * 后台设置页面主类
 *
 * 负责注册菜单、生成选项卡界面并处理设置保存。
 *
 * @package WpGuard
 * @subpackage Admin
 */

namespace WpGuard\Admin;

/**
 * Class Settings
 */
class Settings {
    /**
     * 所有已注册的选项卡对象
     *
     * @var Tab_Base[]
     */
    private $tabs = [];

    /**
     * 初始化：注册选项卡、添加菜单和处理保存请求
     */
    public static function init() {
        $self = new self();
        $self->register_tabs();
        $hook = is_multisite() && \WpGuard\Compatibility\Multisite::is_network_activated() ? 'network_admin_menu' : 'admin_menu';
        add_action( $hook, [ $self, 'add_menu' ] );
        add_action( 'admin_post_wpguard_save_settings', [ $self, 'save_settings' ] );
    }

    /**
     * 注册所有选项卡
     */
    private function register_tabs() {
        $this->tabs[] = new Tab_BasicFilter();
        $this->tabs[] = new Tab_PathProtect();
        $this->tabs[] = new Tab_WhitelistLogs();
    }

    /**
     * 添加后台顶级菜单
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
     * 渲染设置页面及选项卡导航
     */
    public function render_page() {
        $current_tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : $this->tabs[0]->get_slug();
        ?>
        <div class="wrap">
            <h1><?php esc_html_e( 'WpGuard 设置', 'wpguard' ); ?></h1>
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
     * 处理设置保存（通过 admin-post.php）
     */
    public function save_settings() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( '无权操作' );
        }
        $tab_slug = isset( $_POST['tab'] ) ? sanitize_key( $_POST['tab'] ) : '';
        check_admin_referer( 'wpguard_save_' . $tab_slug, 'wpguard_nonce' );

        foreach ( $this->tabs as $tab ) {
            if ( $tab->get_slug() === $tab_slug ) {
                $tab->save( $_POST['settings'] ?? [] );
                break;
            }
        }

        $redirect_url = add_query_arg(
            [ 'page' => 'wpguard', 'tab' => $tab_slug, 'saved' => 'true' ],
            is_network_admin() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' )
        );
        wp_safe_redirect( $redirect_url );
        exit;
    }
}