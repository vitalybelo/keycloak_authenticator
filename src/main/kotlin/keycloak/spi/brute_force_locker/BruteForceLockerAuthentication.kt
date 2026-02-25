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


class BruteForceLockerAuthentication: Authenticator {

    companion object {
        private val logger = Logger.getLogger(BruteForceLockerAuthentication::class.java)
    }

    override fun authenticate(context: AuthenticationFlowContext?) {

        if (context == null) return

        logger.debug(">>>> Brute force locker authentication started >>>>")
        val lockerConfig = BruteForceLockerConfig.init(context)
        if (lockerConfig.isConfigured()) {

            logger.debug(">>>> Brute force locker  authentication configured >>>>")
            val provider = context.session.getProvider(InfinispanConnectionProvider::class.java)
            val cache = provider.getCache<String, LoginAttempt>(BRUTE_FORCE_CACHE)

            val attempt = cache[lockerConfig.cacheKey]
            if (attempt != null) {

                attempt.displayLoginAttempts()
                if (attempt.isBlocked) {

                    // выводим сообщение о блокировке
                    attempt.displayBlockedMessage(lockerConfig)

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