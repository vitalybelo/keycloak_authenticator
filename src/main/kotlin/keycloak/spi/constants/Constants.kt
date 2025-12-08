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

    }
}