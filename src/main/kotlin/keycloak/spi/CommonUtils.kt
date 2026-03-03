package keycloak.spi

import keycloak.spi.constants.Constants.Companion.BRUTE_FORCE_CACHE
import keycloak.spi.event_listener.LoginAttempt
import org.infinispan.Cache
import org.keycloak.connections.infinispan.InfinispanConnectionProvider
import org.keycloak.models.KeycloakSession


/**
 * Возвращает ключ поиска записи о блокировке в infinispan
 */
fun getCacheKey(realmId: String, userId: String) = "bf:${realmId}:${userId}"

fun getInfinispanLoginAttemptCache(session: KeycloakSession): Cache<String, LoginAttempt> {

    val cache = session
        .getProvider(InfinispanConnectionProvider::class.java)
        .getCache<String, LoginAttempt>(BRUTE_FORCE_CACHE)
    return cache
}
