package keycloak.spi.trusted_device.remember

import keycloak.spi.constants.Constants
import org.jboss.logging.Logger
import org.keycloak.Config
import org.keycloak.authentication.Authenticator
import org.keycloak.authentication.AuthenticatorFactory
import org.keycloak.authentication.ConfigurableAuthenticatorFactory
import org.keycloak.models.AuthenticationExecutionModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ProviderConfigurationBuilder

class RememberDeviceAuthenticatorFactory : AuthenticatorFactory {

    companion object {
        const val PROVIDER_ID = "remember-device-authenticator"
        private val logger = Logger.getLogger(RememberDeviceAuthenticatorFactory::class.java)
    }

    override fun create(session: KeycloakSession): Authenticator {
        return RememberDeviceAuthenticator(session)
    }
    override fun init(config: Config.Scope?) {}
    override fun postInit(factory: KeycloakSessionFactory?) {}
    override fun close() {}
    override fun getId(): String = PROVIDER_ID

    override fun getDisplayType(): String = "Remember Device Form"
    override fun getHelpText(): String = "Asks user if they want to trust this device and sets a cookie."
    override fun getReferenceCategory(): String = "cookie"
    override fun isConfigurable(): Boolean = true
    override fun isUserSetupAllowed(): Boolean = false

    override fun getRequirementChoices(): Array<AuthenticationExecutionModel.Requirement> {
        return ConfigurableAuthenticatorFactory.REQUIREMENT_CHOICES
    }

    override fun getConfigProperties(): List<ProviderConfigProperty> {
        return ProviderConfigurationBuilder.create()
            .property()
            .name(Constants.TRUSTED_DEVICE_REM_SWITCH_KEY)
            .label("Remember device enabled")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .helpText("Если \"ON\" - будет выполняться сохранение fingerprint для доверенного устройства в cookie и credential")
            .defaultValue(Constants.TRUSTED_DEVICE_REM_SWITCH_VALUE)
            .add()

            .property()
            .name(Constants.TRUSTED_DEVICE_REM_TTL_KEY)
            .label("Cookie TTL (days)")
            .type(ProviderConfigProperty.INTEGER_TYPE)
            .helpText("Время жизни fingerprint доверенного устройства, после чего он автоматически удаляется из cookie")
            .defaultValue(Constants.TRUSTED_DEVICE_REM_TTL_VALUE)
            .add()

            .property()
            .name(Constants.TRUSTED_DEVICE_RECOVERY_KEY)
            .label("Recovery credential enabled")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .helpText("Если \"ON\" - будет выполняться восстановление fingerprint в credential пользователя, если при прохождении потока обнаружено, что fingerprint существует в cookie, но из учетных данных был вручную удален")
            .defaultValue(Constants.TRUSTED_DEVICE_RECOVERY_VALUE)
            .add()

            .build()
            .also {
                logger.info("Initialize configuration properties :: Remember Trusted Device")
            }
    }

}