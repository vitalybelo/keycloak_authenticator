package keycloak.spi.brute_force_locker

import keycloak.spi.constants.Constants.Companion.BRUTE_FORCE_CACHE
import keycloak.spi.event_listener.LoginAttempt
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.AuthenticationFlowError
import org.keycloak.authentication.Authenticator
import org.keycloak.connections.infinispan.InfinispanConnectionProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import java.util.concurrent.TimeUnit


class BruteForceLockerAuthentication: Authenticator {

    companion object {
        private val logger = Logger.getLogger(BruteForceLockerAuthentication::class.java)
    }

    override fun authenticate(context: AuthenticationFlowContext?) {

        if (context == null) return

        val config = BruteForceLockerConfig.init(context)
        if (config.isConfigured()) {

            val cacheKey = config.cacheKey()
            logger.info("User = \"${config.username}\"")
            logger.info("UserId = \"${config.userId}\"")
            logger.info("RealmId = \"${config.realmId}\"")
            logger.info("CacheKey = \"$cacheKey\"")

            val provider = context.session.getProvider(InfinispanConnectionProvider::class.java)
            val cache = provider.getCache<String, LoginAttempt>(BRUTE_FORCE_CACHE)

            val userLoginAttempt = cache[cacheKey]
            if (userLoginAttempt != null) {
                logger.info("UserLoginAttempt = ${userLoginAttempt.failures}")
                logger.info("UserLoginAttempt = ${userLoginAttempt.isBlocked}")

                if (userLoginAttempt.isBlocked) {
                    val remainingMillis = (userLoginAttempt.unlockTime ?: 0L) - System.currentTimeMillis()
                    if (remainingMillis > 0) {
                        val minutes = TimeUnit.MILLISECONDS.toMinutes(remainingMillis)
                        val seconds = TimeUnit.MILLISECONDS.toSeconds(remainingMillis) % 60
                        val timeMessage = if (minutes > 0) {
                            "$minutes мин. $seconds сек."
                        } else {
                            "$seconds сек."
                        }

                        logger.warn("Вход заблокирован для ${config.username} на $timeMessage мин")
                    }

                    val challenge = context.form()
                        .setError("User is temporarily blocked due to too many failed login attempts. Please try again later.")
                        .createLoginUsername()

                    // Прерываем процесс
                    context.failureChallenge(AuthenticationFlowError.USER_TEMPORARILY_DISABLED, challenge)
                }
            }
        }
        context.success()
    }


    override fun action(context: AuthenticationFlowContext?) {
    }

    override fun requiresUser(): Boolean {
        return false
    }

    override fun configuredFor(
        session: KeycloakSession?,
        realm: RealmModel?,
        user: UserModel?
    ): Boolean {
        return true
    }

    override fun setRequiredActions(
        session: KeycloakSession?,
        realm: RealmModel?,
        user: UserModel?
    ) {
    }

    override fun close() {
    }

}