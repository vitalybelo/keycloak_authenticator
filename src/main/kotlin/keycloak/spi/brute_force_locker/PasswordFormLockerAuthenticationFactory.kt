package keycloak.spi.brute_force_locker

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
 * Фабрика аутентификатора кастомной формы ввода пароля и мгновенной
 * проверкой на неуспешные попыткам входа
 * @author Belotserkovskii Vitaly (c) 26.02.2026
 */
@AutoService(AuthenticatorFactory::class)
class PasswordFormLockerAuthenticationFactory : AuthenticatorFactory {

    companion object {
        private const val PROVIDER_ID = Constants.BRUTE_FORCE_PASSWORD_FORM_ID
        private val logger = Logger.getLogger(PasswordFormLockerAuthenticationFactory::class.java)
    }

    override fun create(session: KeycloakSession?): Authenticator? {
        if (session == null) return null
        return PasswordFormLockerAuthentication(session)
    }

    override fun init(config: Config.Scope?) {
        logger.info(">>>> INIT >>>>")
    }

    override fun postInit(sessionFactory: KeycloakSessionFactory) {
    }

    override fun close() {
        logger.info(">>>> CLOSE >>>>")
    }

    override fun getId(): String {
        return PROVIDER_ID
    }

    override fun getDisplayType(): String = "Password Form & Brute Force Locker"
    override fun getHelpText(): String = "Password Form with checkout login failures"
    override fun getReferenceCategory(): String = "blocker"

    override fun isConfigurable(): Boolean = true
    override fun isUserSetupAllowed(): Boolean = true

    override fun getRequirementChoices(): Array<out AuthenticationExecutionModel.Requirement?>? {
        return ConfigurableAuthenticatorFactory.REQUIREMENT_CHOICES
    }

    @Suppress("DuplicatedCode")
    override fun getConfigProperties(): List<ProviderConfigProperty?>? {
        return ProviderConfigurationBuilder.create()
            .property()
            .name(Constants.BF_CONFIG_SWITCH_KEY)
            .label("Brute force switch")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .helpText("Если \"ON\" - будет выполняться проверка на количество ошибок входа")
            .defaultValue(Constants.BF_CONFIG_SWITCH_VALUE)
            .add()

            .property()
            .name(Constants.BF_CONFIG_MAX_FAILURES_KEY)
            .label("Login errors max count")
            .type(ProviderConfigProperty.INTEGER_TYPE)
            .helpText("После скольких ошибок входа, блокировать пользователя")
            .defaultValue(Constants.BF_CONFIG_MAX_FAILURES_VALUE)
            .add()

            .property()
            .name(Constants.BF_CONFIG_BLOCK_MINUTES_KEY)
            .label("Maximum period of blocking in minutes")
            .type(ProviderConfigProperty.INTEGER_TYPE)
            .helpText("Максимальное время, на которое блокируется пользователь")
            .defaultValue(Constants.BF_CONFIG_BLOCK_MINUTES_VALUE)
            .add()

            .property()
            .name(Constants.BF_CONFIG_RESET_MINUTES_KEY)
            .label("Reset time in minutes")
            .type(ProviderConfigProperty.INTEGER_TYPE)
            .helpText("Время в минутах, в течение которого сбрасываются разовые ошибки")
            .defaultValue(Constants.BF_CONFIG_RESET_MINUTES_VALUE)

            .add()
            .build()
            .also {
                logger.info("Initialize configuration properties :: Brute Force login failures logic")
            }
    }


}