package keycloak.spi.telegram.resource

import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.services.resource.RealmResourceProvider
import org.keycloak.services.resource.RealmResourceProviderFactory

/**
 * Фабрика обработчика ответов, поступивших от Unicredit CA 2FA бота
 */
class TelegramResourceProviderFactory : RealmResourceProviderFactory {

    override fun create(session: KeycloakSession): RealmResourceProvider {
        return TelegramResourceProvider(session)
    }

    override fun init(config: Config.Scope?) {}
    override fun postInit(factory: KeycloakSessionFactory?) {}
    override fun close() {}
    override fun getId(): String = "telegram" // это типа @RequestMapping в контроллерах, будет частью URL
}