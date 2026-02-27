package keycloak.spi.brute_force_locker

import jakarta.ws.rs.core.Response
import keycloak.spi.constants.Constants.Companion.BRUTE_FORCE_CACHE
import keycloak.spi.event_listener.LoginAttempt
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.FlowStatus
import org.keycloak.authentication.authenticators.browser.PasswordForm
import org.keycloak.connections.infinispan.InfinispanConnectionProvider
import org.keycloak.models.KeycloakSession


class PasswordFormLockerAuthentication(
    session: KeycloakSession
) : PasswordForm(session) {

    companion object {
        private val logger = Logger.getLogger(PasswordFormLockerAuthentication::class.java)
        const val LOCKER_ERROR = "Учетная запись временно заблокирована из-за множества неудачных попыток"
    }

    override fun authenticate(context: AuthenticationFlowContext?) {

        if (context == null) return
        if (context.user != null && isUserLockedOut(context)) {

            val challenge: Response? = context.form()
                .setError(LOCKER_ERROR)
                .createLoginPassword()

            context.forceChallenge(challenge)
            return
        }
        super.authenticate(context)
    }


    override fun action(context: AuthenticationFlowContext?) {

        if (context == null) return
        super.action(context)

        if (context.status != FlowStatus.SUCCESS) {

            // Если после этого инкремента пользователь превысил лимит,
            // можно прямо здесь заблокировать его и изменить ответ (challenge)
            if (isUserLockedOut(context)) {
                val challenge = context.form()
                    .setError(LOCKER_ERROR)
                    .createLoginPassword()

                context.forceChallenge(challenge)
            }
        }
    }


    private fun isUserLockedOut(context: AuthenticationFlowContext?): Boolean {

        if (context == null) return false
        val lockerConfig = BruteForceLockerConfig.init(context)
        if (lockerConfig.isConfigured()) {

            logger.debug(">>>> Password brute force locker authentication configured >>>>")
            val provider = context.session.getProvider(InfinispanConnectionProvider::class.java)
            val cache = provider.getCache<String, LoginAttempt>(BRUTE_FORCE_CACHE)

            val attempt = cache[lockerConfig.cacheKey]
            if (attempt != null) {
                if (attempt.isBlocked) {
                    attempt.displayBlockedMessage(lockerConfig)
                    return true
                } else {
                    attempt.displayLoginAttempts()
                }
            }
        }
        return false
    }

}