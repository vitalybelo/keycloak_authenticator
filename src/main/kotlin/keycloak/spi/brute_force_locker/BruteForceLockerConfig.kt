package keycloak.spi.brute_force_locker

import keycloak.spi.constants.Constants
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext

data class BruteForceLockerConfig(

    val isSwitchedOn: Boolean,
    val failureNumbers: Int,
    val blockDurationMinutes: Long,
    val resetDurationMinutes: Long,
    val quickLoginCheckMillis: Long,
    val quickLoginBlockMinutes: Long,
    val isRequired: Boolean,
    val username: String,
    val realmId: String,
    val userId: String,
    val cacheKey: String

) {
    companion object {

        private val logger = Logger.getLogger(BruteForceLockerConfig::class.java)

        fun init(context: AuthenticationFlowContext): BruteForceLockerConfig {

            val realmId = context.realm?.id ?: Constants.UNKNOWN_REALM
            val userId = context.user?.id ?: Constants.UNKNOWN_USER
            val username = context.user?.username ?: Constants.ANONYMOUS
            val cacheKey = "bf:$realmId:$userId"

            val config = context.authenticatorConfig
            val bruteForceLockerConfig = BruteForceLockerConfig(

                isSwitchedOn = config?.config[Constants.BF_CONFIG_SWITCH_KEY]?.toBoolean() ?: Constants.BF_CONFIG_SWITCH_VALUE,
                failureNumbers = config?.config?.get(Constants.BF_CONFIG_MAX_FAILURES_KEY)?.toInt() ?: Constants.BF_CONFIG_MAX_FAILURES_VALUE,
                blockDurationMinutes = config?.config?.get(Constants.BF_CONFIG_BLOCK_MINUTES_KEY)?.toLong() ?: Constants.BF_CONFIG_BLOCK_MINUTES_VALUE,
                resetDurationMinutes = config?.config?.get(Constants.BF_CONFIG_RESET_MINUTES_KEY)?.toLong() ?: Constants.BF_CONFIG_RESET_MINUTES_VALUE,
                quickLoginCheckMillis = config?.config?.get(Constants.BF_CONFIG_QUICK_CHECK_KEY)?.toLong() ?: Constants.BF_CONFIG_QUICK_CHECK_VALUE,
                quickLoginBlockMinutes = config?.config?.get(Constants.BF_CONFIG_QUICK_BLOCK_KEY)?.toLong() ?: Constants.BF_CONFIG_QUICK_BLOCK_VALUE,
                isRequired = context.execution?.isRequired ?: true,
                username = username,
                realmId = realmId,
                userId = userId,
                cacheKey = cacheKey
            )

            logger.debug(""">>>> 
                | Authentication start with config
                | ---------------------------------------------------------------------
                | Username = $username 
                | Cache key = $cacheKey
                |
                | isSwitchedOn = ${bruteForceLockerConfig.isSwitchedOn}
                | failureNumbers = ${bruteForceLockerConfig.failureNumbers}
                | blockDurationMinutes = ${bruteForceLockerConfig.blockDurationMinutes}
                | resetDurationMinutes = ${bruteForceLockerConfig.resetDurationMinutes}
                | quickLoginCheckMillis = ${bruteForceLockerConfig.quickLoginCheckMillis}
                | quickLoginBlockMinutes = ${bruteForceLockerConfig.quickLoginBlockMinutes}
                | isRequired = ${bruteForceLockerConfig.isRequired}
                | ---------------------------------------------------------------------
            """.trimIndent()
            )
            return bruteForceLockerConfig
        }
    }

    fun isConfigured() =
        (this.realmId != Constants.UNKNOWN_REALM && this.userId != Constants.UNKNOWN_USER)
            && isSwitchedOn && isRequired

}