package keycloak.spi.trusted_device.resource

import org.keycloak.models.KeycloakSession
import org.keycloak.services.resource.RealmResourceProvider

class TrustedDeviceRestProvider(private val session: KeycloakSession) : RealmResourceProvider {

    override fun getResource(): Any {
        return TrustedDeviceResource(session)
    }

    override fun close() {}
}