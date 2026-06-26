<?php
/**
 * "指纹特征检测"设置选项卡
 *
 * @package WpGuard
 * @subpackage Admin
 */

namespace WpGuard\Admin;

/**
 * Class Tab_Fingerprint
 */
class Tab_Fingerprint extends Tab_Base {

    /**
     * 构造函数
     */
    public function __construct() {
        $this->slug       = 'fingerprint';
        $this->title      = __( '指纹检测', 'wpguard' );
        $this->option_key = 'fingerprint';
        $this->defaults   = [
            'enabled'       => 0,
            'block_level'   => 'strict',
            'custom_groups' => [ 'ua', 'path' ],
            'features'      => [
                'c2' => 1,
                'c3' => 0,
                'p1' => 0,
                'p2' => 0,
                'r1' => 0,
                'r2' => 0,
                'r3' => 0,
                'r4' => 0,
                'b1' => 1,
            ],
            'rate_limits'   => [
                'r1' => 300,
                'r2' => 30,
                'r3' => 50,
                'r4' => 20,
            ],
            'block_action'  => 'error',
            'http_code'     => 403,
            'whitelist_ips' => '',
            'log_only'      => 0,
        ];
    }

    /**
     * 渲染选项卡 HTML
     */
    public function render() {
        $settings = $this->get_settings();
        $has_object_cache = wp_using_ext_object_cache();
        ?>
        <form method="post" action="">
            <?php wp_nonce_field( 'wpguard_save_' . $this->slug, 'wpguard_nonce' ); ?>
            <input type="hidden" name="action" value="wpguard_save_settings">
            <input type="hidden" name="tab" value="<?php echo esc_attr( $this->slug ); ?>">

            <?php if ( ! $has_object_cache ) : ?>
            <div class="notice notice-warning inline">
                <p><?php esc_html_e( '⚠️ 检测到未启用 Redis/Memcached 等外部对象缓存。频率特征（R1-R4）需要外部缓存支持，未启用时将自动跳过。建议配置对象缓存以提升性能。', 'wpguard' ); ?></p>
            </div>
            <?php endif; ?>

            <table class="form-table">
                <!-- 总开关 -->
                <tr>
                    <th scope="row"><?php esc_html_e( '启用指纹检测', 'wpguard' ); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="settings[enabled]" value="1" <?php checked( 1, $settings['enabled'] ); ?>>
                            <?php esc_html_e( '启用指纹特征检测引擎，识别恶意请求。', 'wpguard' ); ?>
                        </label>
                    </td>
                </tr>
            </table>

            <hr>

            <!-- 封禁级别 -->
            <h3><?php esc_html_e( '封禁级别', 'wpguard' ); ?></h3>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php esc_html_e( '触发条件', 'wpguard' ); ?></th>
                    <td>
                        <p>
                            <label>
                                <input type="radio" name="settings[block_level]" value="loose" <?php checked( 'loose', $settings['block_level'] ); ?>>
                                <?php esc_html_e( '宽松模式 — 满足任意 2 组特征即封禁（误杀率略高）', 'wpguard' ); ?>
                            </label>
                        </p>
                        <p>
                            <label>
                                <input type="radio" name="settings[block_level]" value="strict" <?php checked( 'strict', $settings['block_level'] ); ?>>
                                <?php esc_html_e( '严格模式 — 满足任意 3 组特征即封禁（推荐，误杀率低）', 'wpguard' ); ?>
                            </label>
                        </p>
                        <p>
                            <label>
                                <input type="radio" name="settings[block_level]" value="custom" <?php checked( 'custom', $settings['block_level'] ); ?>>
                                <?php esc_html_e( '自定义模式 — 指定哪几组特征同时命中时封禁', 'wpguard' ); ?>
                            </label>
                        </p>
                    </td>
                </tr>

                <!-- 自定义组合 -->
                <tr id="custom-groups-row" style="<?php echo $settings['block_level'] === 'custom' ? '' : 'display:none;'; ?>">
                    <th scope="row"><?php esc_html_e( '自定义组合', 'wpguard' ); ?></th>
                    <td>
                        <p class="description"><?php esc_html_e( '选择需要同时命中的特征组：', 'wpguard' ); ?></p>
                        <p>
                            <label><input type="checkbox" name="settings[custom_groups][]" value="ua" <?php echo in_array( 'ua', (array) $settings['custom_groups'], true ) ? 'checked' : ''; ?>> <?php esc_html_e( 'UA 特征组 (C2, C3)', 'wpguard' ); ?></label><br>
                            <label><input type="checkbox" name="settings[custom_groups][]" value="path" <?php echo in_array( 'path', (array) $settings['custom_groups'], true ) ? 'checked' : ''; ?>> <?php esc_html_e( '路径特征组 (P1, P2)', 'wpguard' ); ?></label><br>
                            <label><input type="checkbox" name="settings[custom_groups][]" value="crawler" <?php echo in_array( 'crawler', (array) $settings['custom_groups'], true ) ? 'checked' : ''; ?>> <?php esc_html_e( '爬虫特征组 (B1)', 'wpguard' ); ?></label><br>
                            <label><input type="checkbox" name="settings[custom_groups][]" value="rate" <?php echo in_array( 'rate', (array) $settings['custom_groups'], true ) ? 'checked' : ''; ?>> <?php esc_html_e( '频率特征组 (R1-R4)', 'wpguard' ); ?></label>
                        </p>
                    </td>
                </tr>
            </table>

            <hr>

            <!-- 各特征开关 -->
            <h3><?php esc_html_e( '特征开关', 'wpguard' ); ?></h3>
            <table class="form-table">
                <!-- UA 特征 -->
                <tr>
                    <th scope="row"><?php esc_html_e( 'UA 特征', 'wpguard' ); ?></th>
                    <td>
                        <label><input type="checkbox" name="settings[features][c2]" value="1" <?php checked( 1, $settings['features']['c2'] ); ?>> <?php esc_html_e( 'C2 - 老旧浏览器 UA（IE≤8, Firefox≤3, Chrome≤1, Safari≤525）', 'wpguard' ); ?></label><br>
                        <label><input type="checkbox" name="settings[features][c3]" value="1" <?php checked( 1, $settings['features']['c3'] ); ?>> <?php esc_html_e( 'C3 - UA 高频轮换（同一 IP 300 秒内 3 种以上不同 UA）', 'wpguard' ); ?></label>
                        <p class="description"><?php esc_html_e( 'C3 需要缓存支持，会产生少量 IO。', 'wpguard' ); ?></p>
                    </td>
                </tr>

                <!-- 路径特征 -->
                <tr>
                    <th scope="row"><?php esc_html_e( '路径特征', 'wpguard' ); ?></th>
                    <td>
                        <label><input type="checkbox" name="settings[features][p1]" value="1" <?php checked( 1, $settings['features']['p1'] ); ?>> <?php esc_html_e( 'P1 - 仅扫描脚本文件（连续 5 次以上仅请求 .php/.asp 等脚本）', 'wpguard' ); ?></label><br>
                        <label><input type="checkbox" name="settings[features][p2]" value="1" <?php checked( 1, $settings['features']['p2'] ); ?>> <?php esc_html_e( 'P2 - 高频敏感路径（60 秒内超过 20 次访问 wp-admin/wp-login 等）', 'wpguard' ); ?></label>
                        <p class="description"><?php esc_html_e( 'P1/P2 需要缓存支持，会产生少量 IO。', 'wpguard' ); ?></p>
                    </td>
                </tr>

                <!-- 爬虫特征 -->
                <tr>
                    <th scope="row"><?php esc_html_e( '爬虫特征', 'wpguard' ); ?></th>
                    <td>
                        <label><input type="checkbox" name="settings[features][b1]" value="1" <?php checked( 1, $settings['features']['b1'] ); ?>> <?php esc_html_e( 'B1 - 伪造 Googlebot（反向DNS+正向DNS双重验证，结果缓存24小时）', 'wpguard' ); ?></label>
                        <p class="description"><?php esc_html_e( '仅对声称是 Googlebot 的请求进行验证。其他爬虫（Bing/Yandex 等）直接放行。', 'wpguard' ); ?></p>
                    </td>
                </tr>

                <!-- 频率特征 -->
                <tr>
                    <th scope="row"><?php esc_html_e( '频率特征', 'wpguard' ); ?> <?php if ( ! $has_object_cache ) : ?><span style="color: #d63638;"><?php esc_html_e( '(需外部缓存)', 'wpguard' ); ?></span><?php endif; ?></th>
                    <td>
                        <?php if ( ! $has_object_cache ) : ?>
                        <p style="color: #d63638;"><?php esc_html_e( '⚠️ 未检测到外部对象缓存，以下特征将自动跳过，不会生效。', 'wpguard' ); ?></p>
                        <?php endif; ?>
                        <label><input type="checkbox" name="settings[features][r1]" value="1" <?php checked( 1, $settings['features']['r1'] ); ?>> <?php esc_html_e( 'R1 - 全局高频请求（阈值: ', 'wpguard' ); ?><input type="number" name="settings[rate_limits][r1]" value="<?php echo esc_attr( $settings['rate_limits']['r1'] ); ?>" min="10" max="9999" class="small-text"> <?php esc_html_e( '次/分钟）', 'wpguard' ); ?></label><br>
                        <label><input type="checkbox" name="settings[features][r2]" value="1" <?php checked( 1, $settings['features']['r2'] ); ?>> <?php esc_html_e( 'R2 - 高频搜索（阈值: ', 'wpguard' ); ?><input type="number" name="settings[rate_limits][r2]" value="<?php echo esc_attr( $settings['rate_limits']['r2'] ); ?>" min="5" max="999" class="small-text"> <?php esc_html_e( '次/分钟）', 'wpguard' ); ?></label><br>
                        <label><input type="checkbox" name="settings[features][r3]" value="1" <?php checked( 1, $settings['features']['r3'] ); ?>> <?php esc_html_e( 'R3 - 高频 404（阈值: ', 'wpguard' ); ?><input type="number" name="settings[rate_limits][r3]" value="<?php echo esc_attr( $settings['rate_limits']['r3'] ); ?>" min="5" max="999" class="small-text"> <?php esc_html_e( '次/分钟）', 'wpguard' ); ?></label><br>
                        <label><input type="checkbox" name="settings[features][r4]" value="1" <?php checked( 1, $settings['features']['r4'] ); ?>> <?php esc_html_e( 'R4 - 高频写操作（POST 到购物车/结账/登录等，阈值: ', 'wpguard' ); ?><input type="number" name="settings[rate_limits][r4]" value="<?php echo esc_attr( $settings['rate_limits']['r4'] ); ?>" min="5" max="999" class="small-text"> <?php esc_html_e( '次/分钟）', 'wpguard' ); ?></label>
                        <p class="description"><?php esc_html_e( '频率特征需要 Redis/Memcached 等外部对象缓存支持，否则自动禁用。', 'wpguard' ); ?></p>
                    </td>
                </tr>
            </table>

            <hr>

            <!-- 拦截方式 -->
            <h3><?php esc_html_e( '拦截方式', 'wpguard' ); ?></h3>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php esc_html_e( '操作', 'wpguard' ); ?></th>
                    <td>
                        <p>
                            <label>
                                <input type="radio" name="settings[block_action]" value="error" <?php checked( 'error', $settings['block_action'] ); ?>>
                                <?php esc_html_e( '返回 HTTP 错误码', 'wpguard' ); ?>
                                <select name="settings[http_code]">
                                    <option value="403" <?php selected( 403, $settings['http_code'] ); ?>>403 Forbidden</option>
                                    <option value="503" <?php selected( 503, $settings['http_code'] ); ?>>503 Service Unavailable</option>
                                </select>
                            </label>
                        </p>
                        <p>
                            <label>
                                <input type="checkbox" name="settings[log_only]" value="1" <?php checked( 1, $settings['log_only'] ); ?>>
                                <?php esc_html_e( '📋 仅记录日志，不拦截（测试模式 — 建议先开启此模式观察几天，确认无误后再关闭）', 'wpguard' ); ?>
                            </label>
                        </p>
                    </td>
                </tr>
            </table>

            <hr>

            <!-- IP 白名单 -->
            <h3><?php esc_html_e( 'IP 白名单', 'wpguard' ); ?></h3>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php esc_html_e( '白名单 IP', 'wpguard' ); ?></th>
                    <td>
                        <textarea name="settings[whitelist_ips]" rows="4" class="large-text code"><?php echo esc_textarea( $settings['whitelist_ips'] ); ?></textarea>
                        <p class="description"><?php esc_html_e( '每行输入一个 IP 地址或 CIDR 范围（如 114.92.0.0/16）。支持 # 注释。白名单中的 IP 跳过所有检测。', 'wpguard' ); ?></p>
                    </td>
                </tr>
            </table>

            <?php submit_button(); ?>
        </form>

        <script type="text/javascript">
        document.addEventListener('DOMContentLoaded', function() {
            var radios = document.querySelectorAll('input[name="settings[block_level]"]');
            var customRow = document.getElementById('custom-groups-row');

            radios.forEach(function(radio) {
                radio.addEventListener('change', function() {
                    if (this.value === 'custom') {
                        customRow.style.display = '';
                    } else {
                        customRow.style.display = 'none';
                    }
                });
            });
        });
        </script>
        <?php
    }

    /**
     * 数据消毒
     *
     * @param array $input 表单提交数据
     * @return array
     */
    protected function sanitize( $input ) {
        $sanitized = [];

        $sanitized['enabled']       = ! empty( $input['enabled'] ) ? 1 : 0;
        $sanitized['block_level']   = in_array( $input['block_level'] ?? '', [ 'loose', 'strict', 'custom' ], true )
            ? $input['block_level']
            : 'strict';
        $sanitized['custom_groups'] = ! empty( $input['custom_groups'] ) && is_array( $input['custom_groups'] )
            ? array_map( 'sanitize_key', $input['custom_groups'] )
            : [];
        $sanitized['log_only']      = ! empty( $input['log_only'] ) ? 1 : 0;
        $sanitized['http_code']     = in_array( (int) ( $input['http_code'] ?? 403 ), [ 403, 503 ], true )
            ? (int) $input['http_code']
            : 403;
        $sanitized['block_action']  = ! empty( $input['block_action'] ) ? sanitize_key( $input['block_action'] ) : 'error';
        $sanitized['whitelist_ips'] = sanitize_textarea_field( $input['whitelist_ips'] ?? '' );

        // 特征开关
        $features_defaults = $this->defaults['features'];
        $sanitized['features'] = [];
        foreach ( $features_defaults as $feat => $default ) {
            $sanitized['features'][ $feat ] = ! empty( $input['features'][ $feat ] ) ? 1 : 0;
        }

        // 频率阈值
        $rate_defaults = $this->defaults['rate_limits'];
        $sanitized['rate_limits'] = [];
        foreach ( $rate_defaults as $rate => $default ) {
            $val = isset( $input['rate_limits'][ $rate ] ) ? (int) $input['rate_limits'][ $rate ] : $default;
            $sanitized['rate_limits'][ $rate ] = max( 1, min( 9999, $val ) );
        }

        return $sanitized;
    }
}
