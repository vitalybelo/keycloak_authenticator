package keycloak.spi.common

import jakarta.ws.rs.core.Response
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.AuthenticationFlowError

class AuthenticationUtils {

    companion object {
        private val logger = Logger.getLogger(AuthenticationUtils::class.java)
    }

    /**
     * Проверяет состояние контекста потока аутентификации, и если он пустой, выдаем ошибку
     * @param context контекст потока аутентификации
     * @return null если поток пустой
     */
    fun contextEnabledOrNull(context: AuthenticationFlowContext?): Boolean? {

        if (context == null) {
            context?.failureChallenge(
                AuthenticationFlowError.INTERNAL_ERROR,
                context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR)
            )
            logger.warn(">>>> Authentication flow unavailable >>>>")
            return null
        }
        return true
    }
}
