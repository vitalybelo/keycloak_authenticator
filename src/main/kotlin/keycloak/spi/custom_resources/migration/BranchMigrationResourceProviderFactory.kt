package keycloak.spi.custom_resources.migration

import org.keycloak.Config
import org.jboss.logging.Logger
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory

/**
 * Фабрика админ ресурса для реализации метода изменения атрибута пользователя migration_flag
 * @author Belotserkovskii Vitalii (c) 07.05.2026
 */
class BranchMigrationResourceProviderFactory: AdminRealmResourceProviderFactory {

    companion object {
        private val logger = Logger.getLogger(BranchMigrationResourceProviderFactory::class.java)
        private const val PROVIDER_ID = "branch"
    }
    override fun create(session: KeycloakSession): AdminRealmResourceProvider {
        return BranchMigrationResourceProvider()
    }

    override fun getId(): String = PROVIDER_ID
    override fun init(config: Config.Scope) { logger.info(">>>> INIT >>>>") }
    override fun postInit(factory: KeycloakSessionFactory) { logger.debug(">>>> POST INIT >>>>") }
    override fun close() { logger.info(">>>> CLOSE >>>>") }
}