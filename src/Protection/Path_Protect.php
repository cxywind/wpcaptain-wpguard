<?php
/**
 * 路径保护模块
 *
 * 拦截对敏感文件、备份文件和包含自定义关键词的 URL 的访问。
 *
 * @package WpGuard
 * @subpackage Protection
 */

namespace WpGuard\Protection;

/**
 * Class Path_Protect
 */
class Path_Protect extends Base_Protection {
    /**
     * 设置
     *
     * @var array
     */
    private $settings;

    /**
     * 内置敏感文件列表
     *
     * @var array
     */
    private $sensitive_files = [
        '.git',
        '.env',
        'wp-config.php',
        'wp-config-sample.php',
        'phpinfo.php',
        'readme.html',
        'license.txt',
        'debug.log',
        'error_log',
        '.DS_Store',
        'wp-content/debug.log',
    ];

    /**
     * 需要拦截的备份/归档文件扩展名
     *
     * @var array
     */
    private $backup_extensions = [ 'zip', 'tar', 'gz', 'bz2', '7z', 'rar', 'sql', 'bak', 'swp', 'old' ];

    /**
     * 构造函数
     */
    public function __construct() {
        $this->settings = \WpGuard\Utils\Helpers::get_settings( 'path_protect', [
            'enable_sensitive_files' => 1,
            'enable_backup_files'    => 1,
            'allowed_download_dirs'  => '',
            'enable_custom_keywords' => 0,
            'custom_keywords'        => '',
        ] );
    }

    /**
     * 执行路径保护检查
     *
     * @return bool
     */
    public function check() {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        $parsed_path = parse_url( $request_uri, PHP_URL_PATH );

        // 敏感文件
        if ( $this->settings['enable_sensitive_files'] && $this->is_sensitive_file( $parsed_path ) ) {
            $this->block( '敏感文件' );
            return true;
        }

        // 备份文件
        if ( $this->settings['enable_backup_files'] && $this->is_backup_file( $parsed_path ) ) {
            $this->block( '备份文件' );
            return true;
        }

        // 自定义关键词
        if ( $this->settings['enable_custom_keywords'] && $this->has_custom_keywords( $request_uri ) ) {
            $this->block( '自定义关键词' );
            return true;
        }

        return false;
    }

    /**
     * 判断路径是否指向敏感文件
     *
     * @param string $path URL 路径部分
     * @return bool
     */
    private function is_sensitive_file( $path ) {
        $path = trim( $path, '/' );
        foreach ( $this->sensitive_files as $file ) {
            if ( $path === $file || false !== strpos( $path, '/' . $file ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断路径是否为备份文件且不在允许目录中
     *
     * @param string $path URL 路径部分
     * @return bool
     */
    private function is_backup_file( $path ) {
        $ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
        if ( ! in_array( $ext, $this->backup_extensions, true ) ) {
            return false;
        }

        // 如果配置了允许目录，则检查当前路径是否在允许范围内
        $allowed_dirs = $this->settings['allowed_download_dirs'];
        if ( ! empty( $allowed_dirs ) ) {
            $allowed = array_map( 'trim', explode( "\n", $allowed_dirs ) );
            foreach ( $allowed as $dir ) {
                $dir = trim( $dir, '/' );
                if ( 0 === strpos( trim( $path, '/' ), $dir ) ) {
                    return false; // 在允许目录内，放行
                }
            }
        }

        return true;
    }

    /**
     * 检查请求 URI 是否包含自定义关键词
     *
     * @param string $uri 完整请求 URI
     * @return bool
     */
    private function has_custom_keywords( $uri ) {
        $keywords = $this->settings['custom_keywords'];
        // 去除可能的转义符，确保换行正确
        $keywords = wp_unslash( $keywords );

        if ( empty( $keywords ) ) {
            return false;
        }

        $lines = array_filter( array_map( 'trim', explode( "\n", $keywords ) ) );

        foreach ( $lines as $word ) {
            if ( false !== stripos( $uri, $word ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * 拦截请求，记录日志并返回 404
     *
     * @param string $reason 原因
     * @param int    $code   HTTP 状态码
     */
    private function block( $reason, $code = 404 ) {
        \WpGuard\Logger\Log_Handler::log( [
            'reason'      => $reason,
            'status_code' => $code,
        ] );
        status_header( $code );
        die( 'Not found.' );
    }
}