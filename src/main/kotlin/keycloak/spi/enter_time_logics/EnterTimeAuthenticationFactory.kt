package keycloak.spi.enter_time_logics

import com.google.auto.service.AutoService
import keycloak.spi.constants.Constants.Companion.ENTER_TIME_PERIOD
import keycloak.spi.constants.Constants.Companion.ENTER_TIME_SWITCH
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
class EnterTimeAuthenticationFactory : AuthenticatorFactory {

    companion object {
        private const val PROVIDER_ID = "enter_timer_logics"
        private val logger = Logger.getLogger(EnterTimeAuthenticationFactory::class.java)
        private val SINGLETON = EnterTimeAuthentication()
    }

    override fun create(p0: KeycloakSession?): Authenticator {
        return SINGLETON
    }

    override fun init(p0: Config.Scope?) {
        logger.info(">>>> INIT >>>>")
    }

    override fun postInit(p0: KeycloakSessionFactory?) {
        logger.info(">>>> POST INIT >>>>")
    }

    override fun close() {
        logger.info(">>>> CLOSE >>>>")
    }

    override fun getId(): String {
        return PROVIDER_ID
    }

    override fun getDisplayType(): String {
        return "Enter Time Attribute Logic"
    }

    override fun getHelpText(): String {
        return "Register enter time for users and do some logic"
    }

    override fun isConfigurable(): Boolean {
        return true
    }

    override fun isUserSetupAllowed(): Boolean {
        return true
    }

    override fun getReferenceCategory(): String {
        return "registration"
    }

    override fun getRequirementChoices(): Array<out AuthenticationExecutionModel.Requirement?>? {
        return ConfigurableAuthenticatorFactory.REQUIREMENT_CHOICES
    }

    override fun getConfigProperties(): List<ProviderConfigProperty?>? {
        return ProviderConfigurationBuilder.create()
            .property()
            .name(ENTER_TIME_SWITCH)
            .label("Enter time switch")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .helpText("Если \"ON\" - будет выполняться проверка периода для смены пароля")
            .defaultValue(true)
            .add()

            .property()
            .name(ENTER_TIME_PERIOD)
            .label("Period in days to force change password")
            .type(ProviderConfigProperty.INTEGER_TYPE)
            .helpText(
                "Если пользователь не входил в приложение более чем заданное " +
                    "количество дней - будет выставлено требование смены пароля")
            .defaultValue(30)

            .add()
            .build()
            .also {
                logger.info("Initialize configuration properties")
            }
    }


}