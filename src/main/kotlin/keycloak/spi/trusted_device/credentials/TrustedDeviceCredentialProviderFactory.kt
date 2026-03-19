package keycloak.spi.trusted_device.credentials

import org.keycloak.credential.CredentialProviderFactory
import org.keycloak.models.KeycloakSession

class TrustedDeviceCredentialProviderFactory : CredentialProviderFactory<TrustedDeviceCredentialProvider> {

    companion object {
        const val PROVIDER_ID = "trusted-device"
    }

    override fun create(session: KeycloakSession): TrustedDeviceCredentialProvider {
        return TrustedDeviceCredentialProvider(session)
    }

    override fun getId(): String = PROVIDER_ID
}