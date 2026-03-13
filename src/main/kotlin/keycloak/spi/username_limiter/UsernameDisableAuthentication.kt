package keycloak.spi.username_limiter

import jakarta.ws.rs.core.Response
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

        if (context == null || context.user == null) return

        val username = context.user.username ?: Constants.ANONYMOUS
        val config = context.authenticatorConfig
        val isCheckEnable = config?.config[Constants.BLOCKING_SWITCH_KEY]?.toBooleanStrictOrNull() ?: Constants.BLOCKING_SWITCH_VALUE
        val restrictedUsernames = config?.config[Constants.BLOCKING_USERNAME_LIST_KEY]?.split("##")?.toSet() ?: emptySet()

        logger.debug(""">>>> 
            | Configuration UsernameDisableAuthentication: 
            | switch ON = $isCheckEnable
            | auth username = $username
            | restricted usernames $restrictedUsernames
        """.trimIndent())

        if (isCheckEnable && restrictedUsernames.isNotEmpty()) {

            val normalizedDisabledUsernames = restrictedUsernames.map { it.lowercase() }
            val usernameLowerCase = username.lowercase()
            if (normalizedDisabledUsernames.contains(usernameLowerCase)) {

                val execution = context.execution
                if (execution.isRequired) {

                    logger.info(">>>> User login = $username is blocked")
                    context.failureChallenge(
                        AuthenticationFlowError.INVALID_USER,
                        context.form().setError("User login \"$username\" blocked by administrator")
                            .createErrorPage(Response.Status.FORBIDDEN)
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


    override fun action(context: AuthenticationFlowContext?) {}

    override fun configuredFor(
        session: KeycloakSession?,
        realm: RealmModel?,
        user: UserModel?
    ): Boolean = !user?.username.isNullOrEmpty()

    override fun requiresUser(): Boolean = true
    override fun setRequiredActions(session: KeycloakSession?, realm: RealmModel?, user: UserModel?) { }
    override fun close() {}

}