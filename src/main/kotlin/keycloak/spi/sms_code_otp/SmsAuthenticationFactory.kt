package keycloak.spi.sms_code_otp

import com.google.auto.service.AutoService
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

/**
 * Фабрика аутентификатора
 * @author Belotserkovskii Vitaly (c) 2025
 */
@AutoService(AuthenticatorFactory::class)
class SmsAuthenticationFactory : AuthenticatorFactory {

    companion object {
        private const val PROVIDER_ID = "sms_2fa_authentication"
        private val logger = Logger.getLogger(SmsAuthenticationFactory::class.java)
        private val SINGLETON = SmsAuthentication()
    }

    override fun create(session: KeycloakSession?): Authenticator {
        return SINGLETON
    }

    override fun init(config: Config.Scope?) {
        logger.info(">>>> INIT >>>>")
    }

    override fun postInit(sessionFactory: KeycloakSessionFactory?) {
        logger.info(">>>> POST INIT >>>>")
    }

    override fun close() {
        logger.info(">>>> CLOSE >>>>")
    }

    override fun getId(): String {
        return PROVIDER_ID
    }

    override fun getDisplayType(): String {
        return "2FA SMS Authentication"
    }

    override fun getHelpText(): String {
        return "2FA User Authentication with SMS code"
    }

    override fun isConfigurable(): Boolean {
        return true
    }

    override fun isUserSetupAllowed(): Boolean {
        return true
    }

    override fun getReferenceCategory(): String {
        return "2FA"
    }

    override fun getRequirementChoices(): Array<out AuthenticationExecutionModel.Requirement?>? {
        return ConfigurableAuthenticatorFactory.REQUIREMENT_CHOICES
    }

    override fun getConfigProperties(): List<ProviderConfigProperty?>? {
        return ProviderConfigurationBuilder.create()
            .property()
            .name(Constants.SMS_STUB_SWITCH)
            .label("Use stub switch")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .helpText("Если \"ON\" - будет использоваться фиктивный СМС код")
            .defaultValue(true)
            .add()

            .property()
            .name(Constants.SMS_CODE_LENGTH)
            .label("Dummy sms stub code length")
            .type(ProviderConfigProperty.INTEGER_TYPE)
            .helpText("Количество знаков генерируемого secret СМС кода")
            .defaultValue(4)
            .add()

            .property()
            .name(Constants.SMS_STUB_CODE)
            .label("Dummy sms stub code value")
            .type(ProviderConfigProperty.STRING_TYPE)
            .helpText("Значение фиктивного СМС кода для прохождения успешной 2FA")
            .defaultValue(1111)
            .add()

            .property()
            .name(Constants.SMS_TTL)
            .label("Timeout waiting for SMS code value")
            .type(ProviderConfigProperty.INTEGER_TYPE)
            .helpText("Значение тайм-аута в секундах, после которого потребуется ввод нового SMS кода")
            .defaultValue(60)

            .add().build()
    }


}