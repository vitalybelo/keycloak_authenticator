package keycloak.spi.sms_code_otp

import org.jboss.logging.Logger
import keycloak.spi.constants.Constants
import org.keycloak.authentication.AuthenticationFlowContext


data class SmsAuthConfig(

    val ttl: Long,
    val expectedCode: String,

    val isStubEnable: Boolean,
    val smsCodeTTL: Long,
    val codeLength: Int,
    val stubCode: String

) {

    companion object {
        private val logger = Logger.getLogger(SmsAuthConfig::class.java)

        fun init(context: AuthenticationFlowContext): SmsAuthConfig {

            val config = context.authenticatorConfig
            val isStubEnable = config?.config[Constants.SMS_STUB_SWITCH_KEY]?.toBooleanStrictOrNull() ?: Constants.SMS_STUB_SWITCH_VALUE
            val codeLength = config?.config[Constants.SMS_CODE_LENGTH_KEY]?.toIntOrNull() ?: Constants.SMS_CODE_LENGTH_VALUE
            val smsCodeTTL = config?.config[Constants.SMS_CODE_TTL_KEY]?.toLongOrNull() ?: Constants.SMS_CODE_TTL_VALUE
            val stubCode = config?.config[Constants.SMS_STUB_CODE_KEY] ?: Constants.SMS_STUB_CODE_VALUE

            logger.debug(""">>>> Sms Authentication config
                | isStubEnable = $isStubEnable
                | codeLength = $codeLength
                | stubCode = $stubCode
                | smsCodeTTL = $smsCodeTTL
            """.trimIndent()
            )
            return SmsAuthConfig(
                Constants.TTL_ABSENT,
                Constants.CODE_ABSENT,
                isStubEnable = isStubEnable,
                smsCodeTTL = smsCodeTTL,
                codeLength = codeLength,
                stubCode = stubCode
            )
        }
    }

    fun display() {
        logger.debug(""">>>> 
            | Action received sms configuration
            | ttl = $ttl
            | code = $expectedCode
            | isStubEnable = $isStubEnable
            | smsCodeTTL = $smsCodeTTL
            | codeLength = $codeLength
            | stubCode = $stubCode
        """.trimIndent())
    }

    fun isNullOrEmpty(): Boolean = (ttl == Constants.TTL_ABSENT || expectedCode == Constants.CODE_ABSENT)

}
