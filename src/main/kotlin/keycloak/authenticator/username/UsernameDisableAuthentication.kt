package keycloak.authenticator.username

import keycloak.authenticator.constants.ConfigurationConstants
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.AuthenticationFlowError
import org.keycloak.authentication.Authenticator
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel


class UsernameDisableAuthentication() : Authenticator {

    companion object {
        private val logger = Logger.getLogger(UsernameDisableAuthentication::class.java)
    }

    override fun authenticate(context: AuthenticationFlowContext?) {

        if (context != null) {

            val config = context.authenticatorConfig
            val session = context.session
            val user = context.user

            logger.info(">>>> Config = $config")
            logger.info(">>>> Session = $session")
            logger.info(">>>> User = $user")

            val username = user?.username
            val disabledUsername =
                config?.config[ConfigurationConstants.NOT_ALLOWED_USERNAME]?.split("##")
            val isCheckEnable = config?.config[ConfigurationConstants.CHECK_TOGGLE]?.toBoolean() ?: false

            logger.info(">>>> toggle = $isCheckEnable")
            logger.info(">>>> username = $username")
            logger.info(">>>> username disabled = $disabledUsername")

            if (isCheckEnable
                && !disabledUsername.isNullOrEmpty() && !username.isNullOrEmpty()) {

                if (disabledUsername.contains(username)) {

                    val execution = context.execution
                    if (execution.isRequired) {

                        logger.info(">>>> User login = $username is blocked")
                        context.failureChallenge(
                            AuthenticationFlowError.INVALID_USER,
                            context.form().setError("User [$username] login blocked by administrator")
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