package keycloak.spi.trusted_device.conditional

import keycloak.spi.constants.Constants
import org.jboss.logging.Logger
import org.keycloak.Config
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory
import org.keycloak.models.AuthenticationExecutionModel
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ProviderConfigurationBuilder

class ConditionalTrustedDeviceAuthenticatorFactory : ConditionalAuthenticatorFactory {

    companion object {
        const val PROVIDER_ID = "conditional-trusted-device"
        private val logger = Logger.getLogger(ConditionalTrustedDeviceAuthenticatorFactory::class.java)
        private val SINGLETON = ConditionalTrustedDeviceAuthenticator()
    }

    override fun getSingleton(): ConditionalTrustedDeviceAuthenticator {
        return SINGLETON
    }

    override fun init(config: Config.Scope?) {}
    override fun postInit(factory: KeycloakSessionFactory?) {}
    override fun close() {}
    override fun getId(): String = PROVIDER_ID

    override fun getDisplayType(): String = "Condition - Device is NOT Trusted"
    override fun getHelpText(): String = "Если устройство окажется доверенным и совпадают fingerprint в cookie и user credentials, дальше этот subflow выполняться не будет"
    override fun getReferenceCategory(): String = "condition"

    override fun isConfigurable(): Boolean = true
    override fun isUserSetupAllowed(): Boolean = false

    override fun getRequirementChoices(): Array<AuthenticationExecutionModel.Requirement> {
        return arrayOf(
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
        )
    }

    override fun getConfigProperties(): List<ProviderConfigProperty> {
        return ProviderConfigurationBuilder.create()
            .property()
            .name(Constants.TRUSTED_DEVICE_AUTH_SWITCH_KEY)
            .label("Trusted device enabled")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .helpText("Если \"ON\" - будет выполняться проверка. Если выключено, условие всегда вернет true (потребуется 2FA).")
            .defaultValue(Constants.TRUSTED_DEVICE_AUTH_SWITCH_VALUE)
            .add()

            .property()
            .name(Constants.TRUSTED_DEVICE_DELETE_SWITCH_KEY)
            .label("Delete fingerprint enabled")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .helpText("Если \"ON\" - принудительно будет удаляться fingerprint устройства из cookie и credential при входе пользователя")
            .defaultValue(Constants.TRUSTED_DEVICE_DELETE_SWITCH_VALUE)
            .add()

            .build()
            .also {
                logger.info("Initialize configuration properties :: Conditional Trusted Device")
            }
    }
}