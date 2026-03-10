package keycloak.spi.constants

import java.time.format.DateTimeFormatter

@Suppress("SpellCheckingInspection")
class Constants {

    companion object {

        const val NATIVE_ENABLED = "native_enabled"
        const val BLOCKING_SWITCH: String = "blocking_switch"
        const val BLOCKING_USERNAME_LIST: String = "blocking_username_list"

        const val ENTER_TIME_SWITCH: String = "enter_time_switch"
        const val ENTER_TIME_PERIOD: String = "30"
        const val ENTER_TIME_ATTRIBUTE: String = "enterTime"
        const val DATE_TIME_PATTERN = "dd-MM-yyyy HH:mm:ssXXX"
        val ENTER_TIME_FORMATTER: DateTimeFormatter = DateTimeFormatter.ofPattern(DATE_TIME_PATTERN)

        const val SMS_STUB_SWITCH = "sms_stub_switch"
        const val SMS_STUB_CODE = "sms_stub_code"
        const val SMS_CODE_LENGTH = "sms_stub_length"
        const val SMS_CODE_TTL = "sms_ttl"
        const val SMS_CODE = "code"
        const val SMS_TTL = "ttl"

        const val ATTRIBUTE_NAME = "attribute_name"
        const val ATTRIBUTE_VALUES = "attribute_value"
        const val ATTRIBUTE_GROUPS = "attribute_groups_enabled"

        const val BRUTE_FORCE_PASSWORD_FORM_ID = "password_brute_force_locker"
        const val BRUTE_FORCE_CACHE ="loginFailures"
        const val BF_CONFIG_SWITCH_KEY = "brute_force_switch"
        const val BF_CONFIG_SWITCH_VALUE = true
        const val BF_CONFIG_MAX_FAILURES_KEY = "max_failures"
        const val BF_CONFIG_MAX_FAILURES_VALUE = 5
        const val BF_CONFIG_BLOCK_MINUTES_KEY = "block_minutes"
        const val BF_CONFIG_BLOCK_MINUTES_VALUE = 10L
        const val BF_CONFIG_RESET_MINUTES_KEY = "reset_minutes"
        const val BF_CONFIG_RESET_MINUTES_VALUE = 120L
        const val BF_CONFIG_QUICK_CHECK_KEY = "quick_login_interval"
        const val BF_CONFIG_QUICK_CHECK_VALUE = 1000L
        const val BF_CONFIG_QUICK_BLOCK_KEY = "quick_block_minutes"
        const val BF_CONFIG_QUICK_BLOCK_VALUE = 1L
        const val BF_CONFIG_CRITICAL_FAILURES_KEY = "critical_failures"
        const val BF_CONFIG_CRITICAL_FAILURES_VALUE = 20
        const val BF_CONFIG_CRITICAL_WINDOW_KEY = "critical_window"
        const val BF_CONFIG_CRITICAL_WINDOW_VALUE = 1L


        const val UNKNOWN_REALM = "unknown_realm"
        const val UNKNOWN_USER = "unknown_user"
        const val ANONYMOUS = "anonymous"

        const val TELEGRAM_SWITCH_KEY = "telegram_switch"
        const val TELEGRAM_SWITCH_VALUE = true
        const val TELEGRAM_CODE_LENGTH_KEY = "telegram_code_length"
        const val TELEGRAM_CODE_LENGTH_VALUE = 6
        const val TELEGRAM_CODE_TTL_KEY = "telegram_code_ttl"
        const val TELEGRAM_CODE_TTL_VALUE = 60
        const val TELEGRAM_BOT_TOKEN = "8719040842:AAFiZKnA0ts82CARQNs2_lWM_DpKt5da0m0"
        const val TELEGRAM_BIND_ACTION_ID = "telegram-bind-action"
        const val TELEGRAM_CHAT_ID_ATTRIBUTE = "telegram_chat_id"
        const val TELEGRAM_AUTH_NOTE_CODE = "telegram_code"
        const val TELEGRAM_AUTH_NOTE_TIME = "telegram_time_millis"


    }
}