<?php
namespace WpGuard\Logger;

/**
 * Class Log_Handler
 * Handles logging of blocked requests with async storage and cleanup.
 */
class Log_Handler {
    /**
     * Table name.
     *
     * @var string
     */
    private static $table = 'wpguard_logs';

    /**
     * Initialize hooks.
     */
    public static function init() {
        // Queue for bulk insert, commit on shutdown.
        add_action( 'shutdown', [ __CLASS__, 'commit_queue' ] );
        // Log queue stored as a global array for this request.
        global $wpguard_log_queue;
        if ( ! is_array( $wpguard_log_queue ) ) {
            $wpguard_log_queue = [];
        }
    }

    /**
     * Create the log table.
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
            PRIMARY KEY (id),
            KEY blog_id (blog_id),
            KEY timestamp (timestamp),
            KEY ip (ip)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql );
    }

    /**
     * Add a log entry to the queue.
     *
     * @param array $data Log data.
     */
    public static function log( $data ) {
        global $wpguard_log_queue;
        $wpguard_log_queue[] = array_merge( [
            'blog_id'     => get_current_blog_id(),
            'timestamp'   => current_time( 'mysql' ),
            'ip'          => \WpGuard\Utils\IP_Utils::get_ip(),
            'ua'          => sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ?? '' ),
            'request_uri' => sanitize_text_field( $_SERVER['REQUEST_URI'] ?? '' ),
            'reason'      => 'unknown',
            'status_code' => 403,
        ], $data );
    }

    /**
     * Commit queued logs to the database.
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
            $placeholders[] = '(%d, %s, %s, %s, %s, %s, %d)';
        }

        $query = "INSERT INTO $table_name (blog_id, timestamp, ip, ua, request_uri, reason, status_code) VALUES ";
        $query .= implode( ', ', $placeholders );

        $wpdb->query( $wpdb->prepare( $query, $values ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $wpguard_log_queue = [];
    }

    /**
     * Daily cleanup: delete logs older than retention days.
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
     * Get log count (for admin display).
     *
     * @return int
     */
    public static function get_log_count() {
        global $wpdb;
        $table_name = $wpdb->prefix . self::$table;
        return (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_name" );
    }
}