package keycloak.spi.event_listener

import com.google.auto.service.AutoService
import keycloak.spi.constants.Constants
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
        private var maxFailures: Int = Constants.BF_CONFIG_MAX_FAILURES_VALUE
        private var blockDurationMinutes: Long = Constants.BF_CONFIG_BLOCK_MINUTES_VALUE
        private var resetDurationMinutes: Long = Constants.BF_CONFIG_RESET_MINUTES_VALUE
        private val logger = Logger.getLogger(CustomEventListenerProviderFactory::class.java)
    }

    override fun create(keycloakSession: KeycloakSession?): EventListenerProvider? {
        if (keycloakSession == null) return null
        return CustomEventListenerProvider(keycloakSession)
    }

    /**
     * #!/bin/bash
     * export KC_SPI_EVENTS_LISTENER_CUSTOM_EVENT_LISTENER_MAX_FAILURES=10
     * export KC_SPI_EVENTS_LISTENER_CUSTOM_EVENT_LISTENER_BLOCK_DURATION_MINUTES=30
     * export KC_SPI_EVENTS_LISTENER_CUSTOM_EVENT_LISTENER_RESET_DURATION_MINUTES=120
     * так задаем параметры окружения, магия сработает и они попадут в init
     *
     * KC_SPI_EVENTS_LISTENER_CUSTOM_EVENT_LISTENER_MAX_FAILURES = max-failures
     * KC_SPI_EVENTS_LISTENER_CUSTOM_EVENT_LISTENER_BLOCK_DURATION_MINUTES = block-duration-minutes
     * KC_SPI_EVENTS_LISTENER_CUSTOM_EVENT_LISTENER_RESET_DURATION_MINUTES = reset-duration-minutes
     */
    override fun init(config: Config.Scope?) {

        // я переделал получение параметров конфигурации через запрос настроек аутентификатора
        // здесь это останется просто для примера, как задавать конфигурацию через параметры env
        if (config != null) {
            maxFailures = config.getInt("max-failures", Constants.BF_CONFIG_MAX_FAILURES_VALUE)
            blockDurationMinutes = config.getLong("block-duration-minutes", Constants.BF_CONFIG_BLOCK_MINUTES_VALUE)
            resetDurationMinutes = config.getLong("reset-duration-minutes", Constants.BF_CONFIG_RESET_MINUTES_VALUE)
        }
        logger.debugf("""
            CustomEventListenerProviderFactory :: Initialized
            | maxFailures = $maxFailures
            | blockDurationMinutes = $blockDurationMinutes
            | resetDurationMinutes = $resetDurationMinutes
        """.trimIndent())
    }

    override fun postInit(sessionFactory: KeycloakSessionFactory?) {
    }

    override fun close() {
        logger.info(">>>> CLOSED >>>>")
    }

    override fun getId(): String {
        return PROVIDER_ID
    }
}