package keycloak.spi.custom_resources.admin

import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory
import org.jboss.logging.Logger


class CustomAdminResourceProviderFactory: AdminRealmResourceProviderFactory {


    companion object {
        private val logger = Logger.getLogger(CustomAdminResourceProviderFactory::class.java)
        private const val PROVIDER_ID = "admin-ext"
    }

    override fun create(session: KeycloakSession?): AdminRealmResourceProvider {
        return CustomAdminResourceProvider()
    }

    override fun init(scopes: Config.Scope?) {
        logger.info(">>>> INITIALIZED >>>>")
    }

    override fun postInit(sessionFactory: KeycloakSessionFactory) {
    }

    override fun close() {
        logger.info(">>>> CLOSED >>>>")
    }

    override fun getId(): String {
        return PROVIDER_ID
    }

}