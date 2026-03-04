package keycloak.spi.brute_force_locker

import jakarta.ws.rs.core.Response
import keycloak.spi.utils.getInfinispanLoginAttemptCache
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.authenticators.browser.PasswordForm
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
        if (isUserLockedOut(context)) {

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

        if (isUserLockedOut(context)) {
            if (isUserLockedOut(context)) {
                val challenge = context.form()
                    .setError(LOCKER_ERROR)
                    .createLoginPassword()

                context.forceChallenge(challenge)
            }
        }
    }


    /**
     * Читает из infinispan состояние ошибок входя для пользователя, для которого подписан контекст.
     * Если в infinispan не найдены записи для пользователя, означает что в течение установленного срока,
     * пользователь не допускал ошибок входа. Если найден кэш для пользователя, выполняется проверка на
     * наличие установленной блокировки, иначе отображается количество ошибок и период из обнуления.
     * @return true если для пользователя установлена временная блокировка
     */
    private fun isUserLockedOut(context: AuthenticationFlowContext?): Boolean {

        if (context == null) return false
        val lockerConfig = BruteForceLockerConfig.init(context)
        if (lockerConfig.isConfigured()) {

            logger.debug(">>>> Password brute force locker authentication configured >>>>")
            val cache = getInfinispanLoginAttemptCache(context.session)
            val attempt = cache[lockerConfig.cacheKey]

            if (attempt != null) {
                if (attempt.isBlocked) {
                    attempt.displayBlockedMessage(lockerConfig)
                    return true
                } else {
                    attempt.displayLoginAttempts()
                }
            } else {
                logger.debug(">>>> User: ${context.user?.username} has not login failures")
            }
        }
        return false
    }

}