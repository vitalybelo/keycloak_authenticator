package keycloak.spi.brute_force_locker

import keycloak.spi.constants.Constants
import org.keycloak.authentication.AuthenticationFlowContext

data class BruteForceLockerConfig(

    val isSwitchedOn: Boolean,
    val failureNumbers: Int,
    val blockingInMinutes: Int,
    val finalResetInMinutes: Int,
    val isRequired: Boolean,
    val username: String?,
    val realmId: String?,
    val userId: String?

) {
    companion object {

        fun init(context: AuthenticationFlowContext): BruteForceLockerConfig {

            val config = context.authenticatorConfig
            return BruteForceLockerConfig(

                isSwitchedOn = config?.config[Constants.BRUTE_FORCE_SWITCH]?.toBoolean() ?: true,
                failureNumbers = config?.config?.get(Constants.BRUTE_FORCE_COUNT)?.toInt() ?: 0,
                blockingInMinutes = config?.config?.get(Constants.BRUTE_FORCE_BLOCK_MINUTES)?.toInt() ?: 5,
                finalResetInMinutes = config?.config?.get(Constants.BRUTE_FORCE_RESET_MINUTES)?.toInt() ?: 120,
                isRequired = context.execution?.isRequired ?: true,
                username = context.user?.username,
                realmId = context.realm?.id,
                userId = context.user?.id,
            )
        }
    }

    fun isConfigured() = (this.realmId != null && this.userId != null) && isSwitchedOn && isRequired

    fun cacheKey(): String = "bf:${this.realmId}:${this.userId}"
}