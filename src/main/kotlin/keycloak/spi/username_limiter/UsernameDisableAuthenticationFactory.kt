package keycloak.spi.username_limiter

import com.google.auto.service.AutoService
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
import keycloak.spi.constants.Constants.Companion.BLOCKING_SWITCH
import keycloak.spi.constants.Constants.Companion.BLOCKING_USERNAME_LIST

/**
 * Фабрика аутентификатора
 * @author Belotserkovskii Vitaly (c) 2025
 */
@AutoService(AuthenticatorFactory::class)
class UsernameDisableAuthenticationFactory : AuthenticatorFactory {

    companion object {
        private const val PROVIDER_ID = "username_blocking_execution"
        private val logger = Logger.getLogger(UsernameDisableAuthenticationFactory::class.java)
        private val SINGLETON = UsernameDisableAuthentication()
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
        return "Username Login Limiter"
    }

    override fun getHelpText(): String {
        return "Username Login Blocker Authenticator"
    }

    override fun isConfigurable(): Boolean {
        return true
    }

    override fun isUserSetupAllowed(): Boolean {
        return true
    }

    override fun getReferenceCategory(): String {
        return "blocker"
    }

    override fun getRequirementChoices(): Array<out AuthenticationExecutionModel.Requirement?>? {
        return ConfigurableAuthenticatorFactory.REQUIREMENT_CHOICES
    }

    override fun getConfigProperties(): List<ProviderConfigProperty?>? {
        return ProviderConfigurationBuilder.create()
            .property()
            .name(BLOCKING_SWITCH)
            .label("Blocking switch")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .helpText("Если \"ON\" - будет выполняться проверка по username")
            .defaultValue(true)
            .add()

            .property()
            .name(BLOCKING_USERNAME_LIST)
            .label("Blocking username list")
            .type(ProviderConfigProperty.MULTIVALUED_STRING_TYPE)
            .helpText("Usernames, that should be blocked")
            .defaultValue("")

            .add()
            .build()
            .also {
                logger.info("Initialize configuration properties")
            }
    }


}