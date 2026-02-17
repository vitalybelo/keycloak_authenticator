package keycloak.spi.custom_resources

import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.services.resource.RealmResourceProvider
import org.keycloak.services.resource.RealmResourceProviderFactory
import org.jboss.logging.Logger

class CustomResourceProviderFactory: RealmResourceProviderFactory {

    companion object {

        private val logger = Logger.getLogger(CustomResourceProviderFactory::class.java)
        private const val PROVIDER_ID = "custom_resources"
    }

    override fun create(session: KeycloakSession?): RealmResourceProvider? {

        return if (session != null) { CustomResourceProvider(session) } else null
    }

    override fun init(config: Config.Scope?) {
        logger.info(">>>> INITIALIZED >>>>")
    }

    override fun postInit(keycloakSessionFactory: KeycloakSessionFactory) {
    }

    override fun close() {
        logger.info(">>>> CLOSED >>>>")
    }

    override fun getId(): String {
        return PROVIDER_ID
    }
}