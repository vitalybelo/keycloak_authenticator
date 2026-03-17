package keycloak.spi.trusted_device

import keycloak.spi.constants.Constants
import org.jboss.logging.Logger
import org.keycloak.authentication.Authenticator
import org.keycloak.authentication.AuthenticatorFactory
import org.keycloak.models.AuthenticationExecutionModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ProviderConfigurationBuilder

class TrustedDeviceAuthenticatorFactory : AuthenticatorFactory {

    companion object {
        const val PROVIDER_ID = "trusted-device-authenticator"
        private val logger = Logger.getLogger(TrustedDeviceAuthenticatorFactory::class.java)
    }

    override fun create(session: KeycloakSession): Authenticator {
        return TrustedDeviceAuthenticator(session)
    }

    override fun init(config: org.keycloak.Config.Scope?) {}
    override fun postInit(factory: KeycloakSessionFactory?) {}
    override fun close() {}
    override fun getId(): String = PROVIDER_ID

    override fun getDisplayType(): String = "Trusted Device Checker"
    override fun getHelpText(): String = "Bypasses OTP if a valid trusted device cookie is present."
    override fun getReferenceCategory(): String = "cookie"
    override fun isConfigurable(): Boolean = true
    override fun isUserSetupAllowed(): Boolean = false

    override fun getRequirementChoices(): Array<AuthenticationExecutionModel.Requirement> {
        // Этот аутентификатор будет работать в режиме Alternative
        return arrayOf(
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
        )
    }

    override fun getConfigProperties(): List<ProviderConfigProperty> {
        return ProviderConfigurationBuilder.create()
            .property()
            .name(Constants.TRUSTED_DEVICE_AUTH_SWITCH_KEY)
            .label("Trusted device enabled")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .helpText("Если \"ON\" - будет выполняться проверка наличия fingerprint доверенного устройства в cookies и credentials, аутентификатор вернет успех если они совпадают")
            .defaultValue(Constants.TRUSTED_DEVICE_AUTH_SWITCH_VALUE)
            .add()

            .property()
            .name(Constants.TRUSTED_DEVICE_DELETE_SWITCH_KEY)
            .label("Hard delete enabled")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .helpText("Если \"ON\" - принудительно будут удаляться все fingerprints из cookie при входе пользователя, credentials сохранятся")
            .defaultValue(Constants.TRUSTED_DEVICE_DELETE_SWITCH_VALUE)
            .add()

            .build()
            .also {
                logger.info("Initialize configuration properties :: Trusted Device Authenticator")
            }
    }

}