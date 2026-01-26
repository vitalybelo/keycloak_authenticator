package keycloak.spi.username_limiter

import keycloak.spi.constants.Constants
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.AuthenticationFlowError
import org.keycloak.authentication.Authenticator
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel


class UsernameDisableAuthentication : Authenticator {

    companion object {
        private val logger = Logger.getLogger(UsernameDisableAuthentication::class.java)
    }

    override fun authenticate(context: AuthenticationFlowContext?) {

        if (context != null) {

            val config = context.authenticatorConfig
            val user = context.user

            logger.info(">>>> User = $user")

            val disabledUsernameList =
                config?.config[Constants.BLOCKING_USERNAME_LIST]?.split("##")?.toSet() ?: emptySet()

            val username = user?.username ?: ""
            val isCheckEnable = config?.config[Constants.BLOCKING_SWITCH]?.toBoolean() ?: false

            logger.info(">>>> toggle = $isCheckEnable")
            logger.info(">>>> username = $username")
            logger.info(">>>> username disabled = $disabledUsernameList")

            if (isCheckEnable
                && disabledUsernameList.isNotEmpty()
                && username.isNotEmpty()) {

                val normalizedDisabledUsernames = disabledUsernameList.map { it.lowercase() }
                val usernameLowerCase = username.lowercase()
                if (normalizedDisabledUsernames.contains(usernameLowerCase)) {

                    val execution = context.execution
                    if (execution.isRequired) {

                        logger.info(">>>> User login = $username is blocked")
                        context.failureChallenge(
                            AuthenticationFlowError.INVALID_USER,
                            context.form().setError("User login \"$username\" blocked by administrator")
                                .createWebAuthnErrorPage()
                        )
                    } else if (execution.isConditional || execution.isAlternative) {
                        context.attempted()
                    }
                    return
                }
            }
            logger.info(">>>> User login = $username is enabled")
            context.success()
        }
    }

    override fun action(context: AuthenticationFlowContext?) {
    }

    override fun requiresUser(): Boolean {
        return true
    }

    override fun configuredFor(
        session: KeycloakSession?,
        realm: RealmModel?,
        user: UserModel?
    ): Boolean {
        return !user?.username.isNullOrEmpty()
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