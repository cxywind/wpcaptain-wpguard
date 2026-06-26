<?php
/**
 * 日志处理类
 *
 * 负责记录被拦截的请求。日志采用异步批量写入，以降低数据库压力。
 * 支持自动清理过期日志。
 *
 * @package WpGuard
 * @subpackage Logger
 */

namespace WpGuard\Logger;

/**
 * Class Log_Handler
 */
class Log_Handler {
    /**
     * 日志表名（不含前缀）
     *
     * @var string
     */
    private static $table = 'wpguard_logs';

    /**
     * 初始化日志处理器
     *
     * 注册 shutdown 钩子用于批量写入日志。
     */
    public static function init() {
        add_action( 'shutdown', [ __CLASS__, 'commit_queue' ] );
        global $wpguard_log_queue;
        if ( ! is_array( $wpguard_log_queue ) ) {
            $wpguard_log_queue = [];
        }
    }

    /**
     * 创建日志数据表
     *
     * 使用 dbDelta 确保表结构升级安全。
     */
    public static function create_table() {
        global $wpdb;
        $table_name = $wpdb->prefix . self::$table;
        $charset_collate = $wpdb->get_charset_collate();

                $sql = "CREATE TABLE $table_name (
            id BIGINT UNSIGNED AUTO_INCREMENT,
            blog_id BIGINT UNSIGNED NOT NULL DEFAULT 1,
            timestamp DATETIME NOT NULL,
            ip VARCHAR(45) NOT NULL,
            ua TEXT NOT NULL,
            request_uri VARCHAR(2048) NOT NULL,
            reason VARCHAR(100) NOT NULL,
            status_code SMALLINT UNSIGNED NOT NULL DEFAULT 403,
            hit_features VARCHAR(100) NOT NULL DEFAULT '',
            perf_ms DECIMAL(10,2) NOT NULL DEFAULT 0.00,
            PRIMARY KEY (id),
            KEY blog_id (blog_id),
            KEY timestamp (timestamp),
            KEY ip (ip)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql );
    }

    /**
     * 记录一条拦截日志
     *
     * 日志会先暂存在全局队列中，等待 shutdown 时批量写入。
     *
     * @param array $data 日志数据（reason, status_code 等）
     */
        public static function log( $data ) {
        global $wpguard_log_queue;
        $wpguard_log_queue[] = array_merge( [
            'blog_id'      => get_current_blog_id(),
            'timestamp'    => current_time( 'mysql' ),
            'ip'           => \WpGuard\Utils\IP_Utils::get_ip(),
            'ua'           => sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ?? '' ),
            'request_uri'  => sanitize_text_field( $_SERVER['REQUEST_URI'] ?? '' ),
            'reason'       => 'unknown',
            'status_code'  => 403,
            'hit_features' => '',
            'perf_ms'      => 0.00,
        ], $data );
    }

    /**
     * 将队列中的日志批量写入数据库
     *
     * 此方法在 PHP shutdown 阶段自动调用。
     */
    public static function commit_queue() {
        global $wpdb, $wpguard_log_queue;
        if ( empty( $wpguard_log_queue ) ) {
            return;
        }

        $table_name = $wpdb->prefix . self::$table;
        $values = [];
        $placeholders = [];
                foreach ( $wpguard_log_queue as $entry ) {
            $values[] = $entry['blog_id'];
            $values[] = $entry['timestamp'];
            $values[] = $entry['ip'];
            $values[] = $entry['ua'];
            $values[] = $entry['request_uri'];
            $values[] = $entry['reason'];
            $values[] = $entry['status_code'];
            $values[] = $entry['hit_features'];
            $values[] = $entry['perf_ms'];
            $placeholders[] = '(%d, %s, %s, %s, %s, %s, %d, %s, %f)';
        }

        $query = "INSERT INTO $table_name (blog_id, timestamp, ip, ua, request_uri, reason, status_code, hit_features, perf_ms) VALUES ";
        $query .= implode( ', ', $placeholders );

        $wpdb->query( $wpdb->prepare( $query, $values ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $wpguard_log_queue = [];
    }

    /**
     * 每日清理过期日志
     *
     * 默认保留 30 天，可通过 'wpguard_log_retention_days' 过滤器修改。
     */
    public static function cleanup_logs() {
        global $wpdb;
        $retention_days = apply_filters( 'wpguard_log_retention_days', 30 );
        $table_name = $wpdb->prefix . self::$table;
        $wpdb->query( $wpdb->prepare(
            "DELETE FROM $table_name WHERE timestamp < DATE_SUB(NOW(), INTERVAL %d DAY)",
            $retention_days
        ) );
    }

    /**
     * 获取当前日志总数（用于后台显示）
     *
     * @return int
     */
    public static function get_log_count() {
        global $wpdb;
        $table_name = $wpdb->prefix . self::$table;
        return (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_name" );
    }
}