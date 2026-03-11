package keycloak.spi.token_mapper

import jakarta.ws.rs.core.Response
import keycloak.spi.utils.getCacheKey
import keycloak.spi.utils.getInfinispanLoginAttemptCache
import org.jboss.logging.Logger
import org.keycloak.events.Errors
import org.keycloak.models.ClientSessionContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.ProtocolMapperModel
import org.keycloak.models.UserModel
import org.keycloak.models.UserSessionModel
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.representations.AccessToken
import org.keycloak.services.ErrorResponseException

class BlockLockedUserProtocolMapper: AbstractOIDCProtocolMapper(), OIDCAccessTokenMapper {

    companion object {
        const val PROVIDER_ID = "infinispan-lock-blocker-mapper"
        private val logger = Logger.getLogger(BlockLockedUserProtocolMapper::class.java)
    }

    override fun getConfigProperties(): List<ProviderConfigProperty> = emptyList()
    override fun getDisplayCategory(): String = "Token mapper"
    override fun getDisplayType(): String = "Brute-force Session Killer"
    override fun getHelpText(): String = "Checks Infinispan for lockout. If locked, kills all user sessions and blocks token issuance."
    override fun getId(): String = PROVIDER_ID


    override fun transformAccessToken(

        token: AccessToken,
        mappingModel: ProtocolMapperModel,
        session: KeycloakSession,
        userSession: UserSessionModel,
        clientSessionCtx: ClientSessionContext

    ): AccessToken {

        checkLockoutAndKillSessions(session, userSession)
        return super.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx)
    }


    private fun checkLockoutAndKillSessions(
        session: KeycloakSession,
        userSession: UserSessionModel
    ) {
        val user = userSession.user ?: return
        val realm = userSession.realm ?: return

        // проверяем наличие записи о блокировке в кэш Infinispan
        logger.debug(">>>> checkLockoutAndKillSessions(): start for user = ${user.username}")

        if (isLockedInInfinispan(session, user)) {
            // пользователь заблокирован, убиваем ВСЕ активные сессии этого пользователя
            logger.warn(">>>> checkLockoutAndKillSessions(): kill all sessions for user = ${user.username}")
            session.sessions().removeUserSessions(realm, user)

            // прерываем флоу, отбиваем запрос
            throw ErrorResponseException(
                Errors.USER_DISABLED,
                "User is temporarily locked due to suspicious activity",
                Response.Status.UNAUTHORIZED
            )
        }
        logger.debug(">>>> checkLockoutAndKillSessions(): success user = ${user.username}")
    }


    /**
     * Проверяет наличие записи о блокировке пользователя в infinispan
     * @param session сессия keycloak
     * @param user учётные данные пользователя
     * @return true если пользователь заблокирован
     */
    private fun isLockedInInfinispan(
        session: KeycloakSession,
        user: UserModel
    ): Boolean {

        val realmId = session.context.realm.id
        val cacheKey = getCacheKey(realmId, user.id)

        val cache = getInfinispanLoginAttemptCache(session)
        val attempt = cache[cacheKey]
        if (attempt != null) {
            logger.debug(">>>> isLockedInInfinispan(): userId = ${user.username} :: failures = ${attempt.failures.size}")
            return attempt.blockType.isBlocked()
        }
        return false
    }

}