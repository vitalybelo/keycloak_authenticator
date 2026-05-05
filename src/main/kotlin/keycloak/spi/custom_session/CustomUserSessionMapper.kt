package keycloak.spi.custom_session

import org.jboss.logging.Logger
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper
import org.keycloak.models.ClientSessionContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.ProtocolMapperModel
import org.keycloak.models.UserSessionModel
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.representations.AccessToken
import org.keycloak.common.util.Time
import org.keycloak.services.managers.AuthenticationManager

/**
 * Кастомный маппер для обогащения пользовательской сессии заметкой об ограничении длительности сессии
 * пользователя, на основании атрибута пользователя session_time. Важно ! Если значение session_time
 * будет превышать глобальную настройку realm - сработает ограничение сессии из глобальной настройки.
 * @author Belotserkovskii Vitalii (c) 05.05.2026
 */
class CustomUserSessionMapper: AbstractOIDCProtocolMapper(), OIDCAccessTokenMapper {

    companion object {
        const val PROVIDER_ID = "custom-user-session-mapper"
        const val LAST_ACTIVITY = "custom_last_activity"
        const val SESSION_TIME = "session_time"
        private val logger = Logger.getLogger(CustomUserSessionMapper::class.java)
    }

    override fun getId(): String = PROVIDER_ID
    override fun getDisplayCategory(): String = "Token mapper"
    override fun getDisplayType(): String = "Custom User Session Modifier"
    override fun getHelpText(): String = "Reads session_time attribute, modifies Access token exp, and writes note to session"
    override fun getConfigProperties(): List<ProviderConfigProperty?> = emptyList()


    override fun transformAccessToken(

        token: AccessToken,
        mappingModel: ProtocolMapperModel,
        session: KeycloakSession,
        userSession: UserSessionModel,
        clientSessionContext: ClientSessionContext

    ): AccessToken {

        manageCustomUserSession(session, userSession, token)
        return super
            .transformAccessToken(token, mappingModel, session, userSession, clientSessionContext)
    }


    /**
     * Вначале читаем атрибут пользователя "session_time" - он хранит ограничение времени сессии пользователя.
     * Если у пользователя есть этот атрибут (задан в секундах), мы проверяем, не истекло ли время его сессии.
     * Если время вышло — физически удаляем сессию из Keycloak и прерываем выдачу токенов пользователю.
     * Если время еще есть — зашиваем абсолютный срок годности в Access Token.
     *
     * @param session ресурс управления сессиями в keycloak (вообще всем админ функционалом)
     * @param userSession текущая пользовательская сессия
     * @param token экземпляр класса jwt токена
     */
    private fun manageCustomUserSession(
        session: KeycloakSession,
        userSession: UserSessionModel,
        token: AccessToken
    ) {
        val user = userSession.user ?: return
        if (user.serviceAccountClientLink != null) return // отсекаем машинные токены

        val username = user.username
        logger.debug(">>>> Start customize session max time for user = $username")

        val customUserSessionMaxString = userSession.user.getFirstAttribute(SESSION_TIME)

        if (customUserSessionMaxString != null) {
            val customUserSessionMaxSeconds = customUserSessionMaxString.toIntOrNull()

            if (customUserSessionMaxSeconds != null) {

                val currentTime = Time.currentTime()

                // Читаем время последнего действия из заметки, которую сделали ниже.
                // Если ее нет (свежий логин) - берем время старта, и вычисляем время завершения сессии
                val lastActivityString = userSession.getNote(LAST_ACTIVITY)
                val lastActivity = lastActivityString?.toIntOrNull() ?: userSession.started
                val idleExp = lastActivity + customUserSessionMaxSeconds

                if (currentTime > idleExp) {

                    userSession.removeNote(LAST_ACTIVITY)
                    //session.sessions().removeUserSession(userSession.realm, userSession)
                    AuthenticationManager.backchannelLogout(session, userSession, true)
                    logger.warn(">>>> User [${username}] session was expired. Logout >>>>")
                    return
                }
                // вычисляем продленное время завершения сессии пользователя
                val newIdleExp = currentTime + customUserSessionMaxSeconds
                // изменяем утверждение в jwt токене
                // сохраняем заметку для следующего раза
                token.exp(newIdleExp.toLong())
                userSession.setNote(LAST_ACTIVITY, currentTime.toString())
                if (logger.isDebugEnabled) {
                    val spendSeconds = currentTime - userSession.started
                    logger.debug(""">>>> User session setup to:
                        | idle expire to = [$newIdleExp]
                        | session live in = $spendSeconds seconds
                        | username = $username 
                        | """.trimMargin()
                    )

                }
            }
        } else {
            logger.debug(">>>> No custom session time attribute found :: user = $username")
        }
    }

}