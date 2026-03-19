package keycloak.spi.trusted_device.remember

import keycloak.spi.constants.Constants
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext

class RememberDeviceConfig(

    val isSwitchOn: Boolean,
    val cookieTtlDays: Long,
    val isRecoveryCredential: Boolean
) {

    companion object {
        private val logger = Logger.getLogger(RememberDeviceConfig::class.java)

        fun init(context: AuthenticationFlowContext): RememberDeviceConfig {

            val config = context.authenticatorConfig
            val isSwitchOn = config?.config[Constants.TRUSTED_DEVICE_REM_SWITCH_KEY]?.toBooleanStrictOrNull() ?: Constants.TRUSTED_DEVICE_REM_SWITCH_VALUE
            val cookieTtlDays = config?.config[Constants.TRUSTED_DEVICE_REM_TTL_KEY]?.toLongOrNull() ?: Constants.TRUSTED_DEVICE_REM_TTL_VALUE
            val isRecoveryCredential = config?.config[Constants.TRUSTED_DEVICE_RECOVERY_KEY]?.toBooleanStrictOrNull() ?: Constants.TRUSTED_DEVICE_RECOVERY_VALUE

            logger.debug(""">>>>
                | Remember Device Config:
                | ---------------------------------------------
                | is Enabled = $isSwitchOn
                | cookie TTL In Days = $cookieTtlDays
                | is Recovery Credential = $isRecoveryCredential
            """.trimIndent())

            return RememberDeviceConfig(
                isSwitchOn = isSwitchOn,
                cookieTtlDays = cookieTtlDays,
                isRecoveryCredential = isRecoveryCredential
            )
        }
    }
}