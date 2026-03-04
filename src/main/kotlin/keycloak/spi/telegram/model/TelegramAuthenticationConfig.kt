package keycloak.spi.telegram.model

import keycloak.spi.constants.Constants
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext
import kotlin.text.toBoolean
import kotlin.text.toInt

data class TelegramAuthenticationConfig(

    val isSwitchedOn: Boolean,
    val ttlSeconds: Int,
    val codeLength: Int

) {

    companion object {

        private val logger = Logger.getLogger(TelegramAuthenticationConfig::class.java)

        fun init(context: AuthenticationFlowContext): TelegramAuthenticationConfig {

            val config = context.authenticatorConfig
            val isSwitchedOn = config?.config[Constants.TELEGRAM_SWITCH_KEY]?.toBoolean() ?: Constants.TELEGRAM_SWITCH_VALUE
            val ttlSeconds = config?.config[Constants.TELEGRAM_CODE_TTL_KEY]?.toInt() ?: Constants.TELEGRAM_CODE_TTL_VALUE
            val codeLength = config?.config[Constants.TELEGRAM_CODE_LENGTH_KEY]?.toInt() ?: Constants.TELEGRAM_CODE_LENGTH_VALUE

            logger.debug(""">>>>
                | Telegram Authentication Config
                | --------------------------------------------
                | isSwitchedOn = $isSwitchedOn
                | codeLength = $codeLength
                | --------------------------------------------
            """.trimIndent())

            return TelegramAuthenticationConfig(
                isSwitchedOn = isSwitchedOn,
                ttlSeconds = ttlSeconds,
                codeLength = codeLength
            )

        }
    }
}