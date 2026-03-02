package keycloak.spi.constants

import java.time.format.DateTimeFormatter

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

        const val UNKNOWN_REALM = "unknown_realm"
        const val UNKNOWN_USER = "unknown_user"
        const val ANONYMOUS = "anonymous"
    }
}