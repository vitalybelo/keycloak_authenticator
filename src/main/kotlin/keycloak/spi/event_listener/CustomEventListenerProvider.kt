package keycloak.spi.event_listener

import keycloak.spi.constants.Constants.Companion.BRUTE_FORCE_CACHE
import keycloak.spi.jackson_mapper.toJsonString
import org.jboss.logging.Logger
import org.keycloak.connections.infinispan.InfinispanConnectionProvider
import org.keycloak.events.Event
import org.keycloak.events.EventListenerProvider
import org.keycloak.events.EventType
import org.keycloak.events.admin.AdminEvent
import org.keycloak.models.KeycloakSession
import java.util.concurrent.TimeUnit


class CustomEventListenerProvider(

    private val session: KeycloakSession?,
    private val maxFailures: Int,
    private val blockDurationMinutes: Long,
    private val resetDurationMinutes: Long

): EventListenerProvider {

    companion object {
        private val logger = Logger.getLogger(CustomEventListenerProvider::class.java)
    }


    /**
     * Регистрация пользовательских событий
     */
    override fun onEvent(event: Event?) {

        val realmName: String = session?.context?.realm?.name ?: "upstream"
        if (event != null) {

            bruteForceRegistrator(event)
            logger.info(">>>> onEvent: ${event.type} in realm: $realmName")
            logger.info(">>>> Event JSON = ${event.toJsonString()}\n")
        }
    }


    /**
     * Регистрация событий администрирования
     * @param adminEvent админ событие
     * @param includeRepresentation флаг наличия representation
     */
    override fun onEvent(

        adminEvent: AdminEvent?,
        includeRepresentation: Boolean
    ) {

        if (adminEvent != null) {
            logger.info(">>>> onAdminEvent: ${adminEvent.operationType}")
            logger.info(">>>> Event JSON = ${adminEvent.toJsonString()}\n")

            val representation: String? = adminEvent.representation
            if (includeRepresentation) {
                try {
                    logger.info(">>>> Representation = ${representation?.toJsonString()}\n")

                } catch (ex: Exception) {
                    logger.error("Exception occurred while handling event :: ${ex.message}, cause = ${ex.cause}")
                }
            }
        }
    }

    override fun close() {
        logger.debug(">>>> CLOSED >>>>>")
    }


    /**
     * Выполняет регистрацию событий неправильного ввода логина или пароля (улучшенный brute force)
     * @param event пользовательское событие
     */
    private fun bruteForceRegistrator(event: Event) {

        if (session == null) return
        if (event.type != EventType.LOGIN_ERROR) return

        val realmId = event.realmId
        val userId = event.userId
        if (userId == null || realmId == null) return

        val cacheKey = "bf:$realmId:$userId"

        val provider = session.getProvider(InfinispanConnectionProvider::class.java)
        val cache = provider.getCache<String, LoginAttempt>(BRUTE_FORCE_CACHE)

        val updatedAttempt = cache.compute(cacheKey) { _, currentAttempt ->
            val newFailures = (currentAttempt?.failures ?: 0) + 1
            val isNowBlocked = newFailures >= maxFailures
            val unlockTimeMillis =
                (System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(blockDurationMinutes))
                .takeIf { isNowBlocked }
            LoginAttempt(
                failures = newFailures,
                isBlocked = isNowBlocked,
                unlockTime = unlockTimeMillis
            )
        }

        // Устанавливаем блокировку в зависимости от флага isBlocked
        if (updatedAttempt != null) {
            if (updatedAttempt.isBlocked) {
                logger.info(""">>>>
                        | Блокировка на $blockDurationMinutes минут, после ${updatedAttempt.failures} попыток: 
                        | Пользователь = $userId
                        | cacheKey = $cacheKey 
                        """.trimIndent()
                )
                // ставим время жизни записи, равное времени блокировки
                cache.put(cacheKey, updatedAttempt, blockDurationMinutes, TimeUnit.MINUTES)
            } else {
                logger.info(""">>>>
                        | Ошибка входа:
                        | Пользователь = $userId
                        | Попытка = ${updatedAttempt.failures}
                     """.trimIndent()
                )
                // окно накопления ошибок (например, 1 час), если блокировки еще нет
                cache.put(cacheKey, updatedAttempt, resetDurationMinutes, TimeUnit.MINUTES)
            }
        }
    }

}