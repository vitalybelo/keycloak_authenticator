package keycloak.spi.trusted_device

import keycloak.spi.constants.Constants
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext

class TrustedDeviceConfig(

    val isSwitchOn: Boolean,
    val isDeleteOn: Boolean
) {

    companion object {
        private val logger = Logger.getLogger(TrustedDeviceConfig::class.java)

        fun init(context: AuthenticationFlowContext): TrustedDeviceConfig {

            val config = context.authenticatorConfig
            val isSwitchOn = config?.config[Constants.TRUSTED_DEVICE_AUTH_SWITCH_KEY]?.toBooleanStrictOrNull() ?: Constants.TRUSTED_DEVICE_AUTH_SWITCH_VALUE
            val isDeleteOn = config?.config[Constants.TRUSTED_DEVICE_DELETE_SWITCH_KEY]?.toBooleanStrictOrNull() ?: Constants.TRUSTED_DEVICE_DELETE_SWITCH_VALUE

            logger.debug(""">>>>
                | Trusted Device Config:
                | -------------------------------
                | is Enabled = $isSwitchOn
                | is Force Delete cookie = $isDeleteOn
            """.trimIndent())

            return TrustedDeviceConfig(isSwitchOn, isDeleteOn)
        }
    }



}


