package keycloak.spi.telegram.auth

import keycloak.spi.constants.Constants
import org.keycloak.Config
import org.keycloak.authentication.Authenticator
import org.keycloak.authentication.AuthenticatorFactory
import org.keycloak.authentication.ConfigurableAuthenticatorFactory
import org.keycloak.models.AuthenticationExecutionModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ProviderConfigurationBuilder
import java.util.logging.Logger

/**
 * Фабрика аутентификатора входа с вторым фактором через telegram
 * @author Belotserkovskii Vitalii (c) 05.03.2026
 */
class TelegramAuthenticatorFactory : AuthenticatorFactory {

    companion object {
        const val PROVIDER_ID = "telegram-authenticator"
        private val logger = Logger.getLogger(TelegramAuthenticatorFactory::class.simpleName)
    }

    override fun create(session: KeycloakSession): Authenticator {
        return TelegramAuthenticator()
    }

    override fun getId(): String = PROVIDER_ID
    override fun getDisplayType(): String = "Telegram 2FA"
    override fun getHelpText(): String = "Запрашивает одноразовый код (OTP), отправленный в Telegram."
    override fun getReferenceCategory(): String = "otp"
    override fun isConfigurable(): Boolean = true
    override fun isUserSetupAllowed(): Boolean = true

    override fun getRequirementChoices(): Array<out AuthenticationExecutionModel.Requirement?>? {
        return ConfigurableAuthenticatorFactory.REQUIREMENT_CHOICES
    }

    override fun getConfigProperties(): List<ProviderConfigProperty> {
        return ProviderConfigurationBuilder.create()
            .property()
            .name(Constants.TELEGRAM_SWITCH_KEY)
            .label("Telegram 2FA enabled")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .helpText("Если \"ON\" - будет выполняться проверка входа по коду через telegram")
            .defaultValue(Constants.TELEGRAM_SWITCH_VALUE)
            .add()

            .property()
            .name(Constants.TELEGRAM_CODE_TTL_KEY)
            .label("Code TTL (in seconds)")
            .type(ProviderConfigProperty.INTEGER_TYPE)
            .helpText("Время жизни одноразового кода в секундах")
            .defaultValue(Constants.TELEGRAM_CODE_TTL_VALUE)
            .add()

            .property()
            .name(Constants.TELEGRAM_CODE_LENGTH_KEY)
            .label("Code length (count digits)")
            .type(ProviderConfigProperty.INTEGER_TYPE)
            .helpText("Количество цифр в временном коде")
            .defaultValue(Constants.TELEGRAM_CODE_LENGTH_VALUE)
            .add()

            .build()
            .also {
                logger.info("Initialize configuration properties :: Telegram Authentication 2FA")
            }
    }

    override fun init(config: Config.Scope?) {}
    override fun postInit(factory: KeycloakSessionFactory?) {}
    override fun close() {}
}