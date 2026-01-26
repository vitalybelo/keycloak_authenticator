package keycloak.spi.utils

import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext

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
            logger.warn(">>>> CRITICAL: Authentication context is null! Cannot proceed. >>>>")
            return null
        }
        return true
    }
}