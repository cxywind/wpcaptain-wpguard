<?php
/**
 * Plugin Name: WpGuard - Intelligent Protection
 * Plugin URI:  https://example.com/wpguard
 * Description: Protects WordPress against CC/DDoS attacks with smart filtering, behavior analysis, and SEO-safe defaults.
 * Version:     1.0.0
 * Author:      Your Name
 * Author URI:  https://example.com
 * License:     GPL-2.0+
 * Text Domain: wpguard
 * Domain Path: /languages
 *
 * WpGuard is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * any later version.
 *
 * WpGuard is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    die;
}

/**
 * Current plugin version.
 */
define( 'WPGUARD_VERSION', '1.0.0' );

/**
 * Plugin base directory path.
 */
define( 'WPGUARD_PATH', plugin_dir_path( __FILE__ ) );

/**
 * Plugin base URL.
 */
define( 'WPGUARD_URL', plugin_dir_url( __FILE__ ) );

/**
 * Minimum required PHP version.
 */
define( 'WPGUARD_MIN_PHP', '7.2' );

// Check PHP version.
if ( version_compare( PHP_VERSION, WPGUARD_MIN_PHP, '<' ) ) {
    add_action( 'admin_notices', 'wpguard_php_version_notice' );
    /**
     * Display PHP version notice.
     */
    function wpguard_php_version_notice() {
        ?>
        <div class="notice notice-error">
            <p><?php echo esc_html( sprintf( __( 'WpGuard requires PHP version %s or higher. Your current version is %s.', 'wpguard' ), WPGUARD_MIN_PHP, PHP_VERSION ) ); ?></p>
        </div>
        <?php
    }
    return;
}

// Load autoloader (simple manual loader).
require_once WPGUARD_PATH . 'src/Core/Singleton.php';
require_once WPGUARD_PATH . 'src/Core/Bootstrap.php';
require_once WPGUARD_PATH . 'src/Compatibility/Multisite.php';
require_once WPGUARD_PATH . 'src/Cache/Cache_Handler.php';
require_once WPGUARD_PATH . 'src/Logger/Log_Handler.php';
require_once WPGUARD_PATH . 'src/Whitelist/Crawler_Whitelist.php';
require_once WPGUARD_PATH . 'src/Utils/Helpers.php';
require_once WPGUARD_PATH . 'src/Utils/IP_Utils.php';
require_once WPGUARD_PATH . 'src/Admin/Tab_Base.php';
require_once WPGUARD_PATH . 'src/Admin/Tab_BasicFilter.php';
require_once WPGUARD_PATH . 'src/Admin/Tab_PathProtect.php';
require_once WPGUARD_PATH . 'src/Admin/Tab_WhitelistLogs.php';
require_once WPGUARD_PATH . 'src/Admin/Settings.php';
require_once WPGUARD_PATH . 'src/Protection/Base_Protection.php';
require_once WPGUARD_PATH . 'src/Protection/Basic_Filter.php';
require_once WPGUARD_PATH . 'src/Protection/Path_Protect.php';
require_once WPGUARD_PATH . 'src/Protection/Protection_Engine.php';

// Boot the plugin.
\WpGuard\Core\Bootstrap::instance();