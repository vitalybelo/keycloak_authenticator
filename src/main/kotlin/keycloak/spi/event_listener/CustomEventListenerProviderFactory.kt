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
        const val PROVIDER_ID = "Custom-Event-Listener"
        private val logger = Logger.getLogger(CustomEventListenerProviderFactory::class.java)
    }

    override fun create(keycloakSession: KeycloakSession?): EventListenerProvider {
        return CustomEventListenerProvider(keycloakSession)
    }

    override fun init(config: Config.Scope?) {
        logger .info(">>>> INIT >>>> ")
    }

    override fun postInit(sessionFactory: KeycloakSessionFactory?) {
        logger.info(">>>> POST INIT >>>>")
    }

    override fun close() {
        logger.info(">>>> CLOSE >>>>")
    }

    override fun getId(): String {
        return PROVIDER_ID
    }
}