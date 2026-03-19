package keycloak.spi.trusted_device.resource

import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.services.resource.RealmResourceProvider
import org.keycloak.services.resource.RealmResourceProviderFactory

class TrustedDeviceRestProviderFactory : RealmResourceProviderFactory {

    companion object {
        const val PROVIDER_ID = "trusted-devices" // путь к нашему API: /realms/{realm}/trusted-devices
    }

    override fun create(session: KeycloakSession): RealmResourceProvider {
        return TrustedDeviceRestProvider(session)
    }

    override fun init(config: Config.Scope?) {}
    override fun postInit(factory: KeycloakSessionFactory?) {}
    override fun close() {}

    override fun getId(): String = PROVIDER_ID
}