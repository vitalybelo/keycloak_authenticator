package keycloak.spi.sms_code_otp

import org.jboss.logging.Logger
import keycloak.spi.constants.Constants
import org.keycloak.authentication.AuthenticationFlowContext
import kotlin.text.toBoolean
import kotlin.text.toInt
import kotlin.text.toLong


data class SmsAuthConfig(

    var ttl: Long? = null,
    var code: String? = null,

    var isStubEnable: Boolean? = null,
    var smsCodeTTL: Long? = null,
    var codeLength: Int? = null,
    var stubCode: String? = null

) {

    companion object {
        private val logger = Logger.getLogger(SmsAuthConfig::class.java)
    }

    fun isNullOrEmpty(): Boolean =
        (ttl == null || code.isNullOrEmpty() || isStubEnable == null
                || smsCodeTTL == null || codeLength == null || stubCode.isNullOrEmpty())

    constructor(context: AuthenticationFlowContext): this() {

        val config = context.authenticatorConfig
        isStubEnable = config?.config[Constants.SMS_STUB_SWITCH]?.toBoolean() ?: true
        codeLength = config?.config[Constants.SMS_CODE_LENGTH]?.toInt() ?: 4
        smsCodeTTL = config?.config[Constants.SMS_TTL]?.toLong() ?: 60
        stubCode = config?.config[Constants.SMS_STUB_CODE] ?: "1111"

        logger.info(">>>> SMS stub switch = $isStubEnable")
        logger.info(">>>> SMS stub length = $codeLength")
        logger.info(">>>> SMS stub code = $stubCode")
        logger.info(">>>> Sms code TTL = $smsCodeTTL")
    }

}
