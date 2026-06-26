<?php
/**
 * 后台设置页面主类
 *
 * 负责注册菜单、生成选项卡界面并处理设置保存。
 * 保存时增加调试日志，便于定位问题。
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
     * 初始化：注册选项卡、添加菜单
     */
    public static function init() {
        $self = new self();
        $self->register_tabs();

        // 根据多站点激活状态和当前后台类型注册菜单
        $menu_hook = is_multisite() && \WpGuard\Compatibility\Multisite::is_network_activated() ? 'network_admin_menu' : 'admin_menu';
        add_action( $menu_hook, [ $self, 'add_menu' ] );
    }

    /**
     * 注册所有选项卡
     */
        private function register_tabs() {
        $this->tabs[] = new Tab_BasicFilter();
        $this->tabs[] = new Tab_PathProtect();
        $this->tabs[] = new Tab_Fingerprint();
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
     * 在渲染页面前检查是否有表单提交，有则处理保存并重定向
     */
    private function maybe_handle_save() {
        if ( ! isset( $_POST['action'] ) || $_POST['action'] !== 'wpguard_save_settings' ) {
            return;
        }

        // 权限验证
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( '无权操作' );
        }

        $tab_slug = isset( $_POST['tab'] ) ? sanitize_key( $_POST['tab'] ) : '';

        // Nonce 验证
        if ( ! isset( $_POST['wpguard_nonce'] ) || ! wp_verify_nonce( $_POST['wpguard_nonce'], 'wpguard_save_' . $tab_slug ) ) {
            $this->safe_redirect( [ 'error' => 'nonce' ] );
        }

        // 执行对应选项卡的保存逻辑
        foreach ( $this->tabs as $tab ) {
            if ( $tab->get_slug() === $tab_slug ) {
                $tab->save( $_POST['settings'] ?? [] );
                break;
            }
        }

        // 保存成功重定向
        $this->safe_redirect( [ 'saved' => 'true' ] );
    }

    /**
     * 安全重定向到设置页面
     *
     * 优先使用 HTTP 重定向，失败时回退为 JavaScript 跳转。
     *
     * @param array $args 额外的查询参数
     */
    private function safe_redirect( $args = [] ) {
        // 彻底清除所有缓冲区
        while ( ob_get_level() ) {
            @ob_end_clean();
        }

        $tab_slug = isset( $_POST['tab'] ) ? sanitize_key( $_POST['tab'] ) : 'basic_filter';
        $base_args = [ 'page' => 'wpguard', 'tab' => $tab_slug ];
        $args = array_merge( $base_args, $args );

        $redirect_url = add_query_arg(
            $args,
            is_network_admin() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' )
        );

        // 尝试 HTTP 重定向
        if ( ! headers_sent() ) {
            @wp_redirect( $redirect_url );
            exit;
        }

        // 如果 headers 已发送，使用 JavaScript 跳转（备用方案）
        echo '<script type="text/javascript">window.location.href = "' . esc_url( $redirect_url ) . '";</script>';
        echo '<p>' . esc_html__( '如果页面没有自动跳转，请点击', 'wpguard' ) . ' <a href="' . esc_url( $redirect_url ) . '">' . esc_html__( '这里', 'wpguard' ) . '</a>.</p>';
        exit;
    }

    /**
     * 渲染设置页面及选项卡导航
     */
    public function render_page() {
        // 优先处理表单提交
        $this->maybe_handle_save();

        $current_tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : $this->tabs[0]->get_slug();
        ?>
        <div class="wrap">
            <h1><?php esc_html_e( 'WpGuard 设置', 'wpguard' ); ?></h1>
            <?php if ( isset( $_GET['saved'] ) && $_GET['saved'] === 'true' ) : ?>
                <div class="notice notice-success is-dismissible">
                    <p><?php esc_html_e( '设置已成功保存。', 'wpguard' ); ?></p>
                </div>
            <?php elseif ( isset( $_GET['error'] ) ) : ?>
                <div class="notice notice-error is-dismissible">
                    <p><?php esc_html_e( '保存时发生错误，请重试。', 'wpguard' ); ?></p>
                </div>
            <?php endif; ?>
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
}