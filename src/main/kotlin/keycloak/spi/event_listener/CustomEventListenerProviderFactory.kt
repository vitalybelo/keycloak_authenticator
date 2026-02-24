package keycloak.spi.event_listener

import com.google.auto.service.AutoService
import org.keycloak.Config
import org.jboss.logging.Logger
import org.keycloak.events.EventListenerProvider
import org.keycloak.events.EventListenerProviderFactory
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory


@AutoService(EventListenerProviderFactory::class)
class CustomEventListenerProviderFactory : EventListenerProviderFactory {

    companion object {
        const val PROVIDER_ID = "custom-event-listener"
        private var maxFailures: Int = 5
        private var blockDurationMinutes: Long = 15L
        private var resetDurationMinutes: Long = 60L
        private val logger = Logger.getLogger(CustomEventListenerProviderFactory::class.java)
    }

    override fun create(keycloakSession: KeycloakSession?): EventListenerProvider {
        return CustomEventListenerProvider(
            keycloakSession,
            maxFailures,
            blockDurationMinutes,
            resetDurationMinutes
        )
    }

    /**
     * #!/bin/bash
     * export KC_SPI_EVENTS_LISTENER_CUSTOM_EVENT_LISTENER_MAX_FAILURES=10
     * export KC_SPI_EVENTS_LISTENER_CUSTOM_EVENT_LISTENER_BLOCK_DURATION_MINUTES=30
     * export KC_SPI_EVENTS_LISTENER_CUSTOM_EVENT_LISTENER_RESET_DURATION_MINUTES=120
     * так задаем параметры окружения, магия сработает и они попадут в init
     */
    override fun init(config: Config.Scope?) {
        if (config != null) {
            // Читаем параметры по их именам (ключи зададим сами, например: max-failures)
            maxFailures = config.getInt("max-failures", 5) ?: 5
            blockDurationMinutes = config.getLong("block-duration-minutes", 15L) ?: 10L
            resetDurationMinutes = config.getLong("reset-duration-minutes", 60L) ?: 120L
        }
        logger .info("""
            CustomEventListenerProviderFactory :: Initialized
            | maxFailures = $maxFailures
            | blockDurationMinutes = $blockDurationMinutes
            | resetDurationMinutes = $resetDurationMinutes
        """.trimIndent())
    }

    override fun postInit(sessionFactory: KeycloakSessionFactory?) {
        logger.info(">>>> POST INITIALIZED >>>>")
    }

    override fun close() {
        logger.info(">>>> CLOSED >>>>")
    }

    override fun getId(): String {
        return PROVIDER_ID
    }
}