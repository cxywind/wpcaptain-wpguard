=== WpGuard - 智能防护系统 ===
Contributors: you
Tags: security, ddos, firewall, cc-attack
Requires at least: 5.0
Tested up to: 6.5
Stable tag: 1.0.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

通过智能过滤、行为分析和 SEO 安全默认值保护 WordPress 免受 CC/DDoS 攻击。

允许保存的权限设置：
 location = /wp-admin/network/admin-post.php {
    allow all;
    include fastcgi.conf;           # 根据你的环境调整
    fastcgi_pass unix:/tmp/php-cgi-74.sock;  # 使用你站点实际的 sock 路径
}