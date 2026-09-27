<?php
/**
 * Plugin Name: AbuseIPDB Spam Reporter
 * Description: Automatically reports the IP of a spammed comment to AbuseIPDB. Handles both manual and automatic (e.g., Akismet) spam flags.
 * Version: 1.2
 * Author: phoenix901
 */

if (!defined('ABSPATH')) {
    exit; // Выход, если доступ к файлу осуществляется напрямую.
}

// --- 1. Настройки API-ключа (без изменений) ---

add_action('admin_init', 'abuseipdb_register_settings');
function abuseipdb_register_settings() {
    register_setting('general', 'abuseipdb_api_key', 'sanitize_text_field');
    add_settings_field('abuseipdb_api_key_field', 'AbuseIPDB API Key', 'abuseipdb_api_key_field_html', 'general', 'default');
}

function abuseipdb_api_key_field_html() {
    $value = get_option('abuseipdb_api_key', '');
    echo '<input type="text" id="abuseipdb_api_key_field" name="abuseipdb_api_key" class="regular-text" value="' . esc_attr($value) . '" />';
    echo '<p class="description">Получите бесплатный ключ API на <a href="https://www.abuseipdb.com/account/api" target="_blank">AbuseIPDB.com</a>.</p>';
}


// --- 2. Основная логика (улучшенная и объединенная) ---

/**
 * Перехватывает ручную пометку "Спам".
 */
add_action('transition_comment_status', 'abuseipdb_handle_spam_transition', 10, 3);
function abuseipdb_handle_spam_transition($new_status, $old_status, $comment) {
    // Срабатываем только при переходе в "спам"
    if ($new_status === 'spam' && $new_status !== $old_status) {
        abuseipdb_maybe_report_comment($comment->comment_ID);
    }
}

/**
 * Перехватывает комментарии, помеченные как спам плагинами (например, Akismet)
 * в момент их создания.
 */
add_action('wp_insert_comment', 'abuseipdb_handle_spam_on_insert', 10, 2);
function abuseipdb_handle_spam_on_insert($comment_id, $comment_object) {
    // Проверяем, был ли комментарий сразу помечен как спам
    if (isset($comment_object->comment_approved) && $comment_object->comment_approved === 'spam') {
        abuseipdb_maybe_report_comment($comment_id);
    }
}


/**
 * Центральная функция для отправки репорта.
 * Проверяет все условия и отправляет запрос.
 * @param int $comment_id ID комментария.
 */
function abuseipdb_maybe_report_comment($comment_id) {
    // Получаем объект комментария по ID
    $comment = get_comment($comment_id);
    if (!$comment) {
        return;
    }

    // 1. Проверка: убедимся, что мы еще не отправляли репорт.
    $already_reported = get_comment_meta($comment->comment_ID, '_abuseipdb_reported', true);
    if ($already_reported) {
        return;
    }

    // 2. Получаем API-ключ.
    $api_key = get_option('abuseipdb_api_key');
    if (empty($api_key)) {
        return;
    }

    // 3. Проверяем IP. Отправлять в AbuseIPDB частные и зарезервированные
    //    адреса бессмысленно — API их отклоняет, а мы бы пометили комментарий
    //    как "отправленный" и потеряли реальный репорт.
    $ip_address = $comment->comment_author_IP;
    if (!filter_var($ip_address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return;
    }

    // 4. Готовим данные для отправки.
    //    mb_substr, а не substr: обычный substr режет UTF-8 посередине символа,
    //    и на кириллических комментариях в JSON уходила битая строка.
    //    Лимит AbuseIPDB на поле comment — 1024 символа, префикс занимает 24.
    $comment_content = wp_strip_all_tags((string) $comment->comment_content);
    $body = [
        'ip' => $ip_address,
        'categories' => '10,21', // 10 = Web Spam, 21 = Web App Attack
        'comment' => 'WordPress comment spam: ' . mb_substr($comment_content, 0, 950, 'UTF-8')
    ];
    $headers = [
        'Accept' => 'application/json',
        'Key'    => $api_key
    ];

    // 5. Отправляем запрос и ставим флаг ТОЛЬКО при успехе.
    //    Раньше стояло 'blocking' => false, а флаг ставился безусловно, поэтому
    //    единственная сетевая ошибка навсегда помечала комментарий как
    //    отправленный, и репорт терялся безвозвратно.
    $response = wp_remote_post('https://api.abuseipdb.com/api/v2/report', [
        'method'   => 'POST',
        'headers'  => $headers,
        'body'     => $body,
        'timeout'  => 8,
        'blocking' => true,
    ]);

    if (is_wp_error($response)) {
        return;
    }

    $code = (int) wp_remote_retrieve_response_code($response);
    if ($code >= 200 && $code < 300) {
        update_comment_meta($comment->comment_ID, '_abuseipdb_reported', true);
    }
}
