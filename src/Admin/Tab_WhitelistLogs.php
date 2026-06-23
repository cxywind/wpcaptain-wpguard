<?php
/**
 * “白名单与日志”设置选项卡（第一阶段为预览占位）
 *
 * @package WpGuard
 * @subpackage Admin
 */

namespace WpGuard\Admin;

/**
 * Class Tab_WhitelistLogs
 */
class Tab_WhitelistLogs extends Tab_Base {
    /**
     * 构造函数
     */
    public function __construct() {
        $this->slug       = 'whitelist_logs';
        $this->title      = __( '白名单与日志', 'wpguard' );
        $this->option_key = 'whitelist_logs';
        $this->defaults   = [];
    }

    /**
     * 渲染选项卡内容
     */
    public function render() {
        $log_count = \WpGuard\Logger\Log_Handler::get_log_count();
        ?>
        <div class="wrap">
            <h3><?php esc_html_e( '日志概览', 'wpguard' ); ?></h3>
            <p><?php echo esc_html( sprintf( __( '已拦截请求总数：%d', 'wpguard' ), $log_count ) ); ?></p>
            <p><?php esc_html_e( '日志将每天自动清理，默认保留 30 天。', 'wpguard' ); ?></p>
            <p><em><?php esc_html_e( '完整的日志查看器和白名单管理将在后续版本中推出。', 'wpguard' ); ?></em></p>
        </div>
        <?php
    }
}