package keycloak.spi.brute_force_locker

import com.google.auto.service.AutoService
import keycloak.spi.constants.Constants.Companion.BRUTE_FORCE_BLOCK_MINUTES
import keycloak.spi.constants.Constants.Companion.BRUTE_FORCE_COUNT
import keycloak.spi.constants.Constants.Companion.BRUTE_FORCE_RESET_MINUTES
import keycloak.spi.constants.Constants.Companion.BRUTE_FORCE_SWITCH
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
 * Фабрика аутентификатора, блокировщика входа по неуспешным попыткам
 * @author Belotserkovskii Vitaly (c) 24.02.2026
 */
@AutoService(AuthenticatorFactory::class)
class BruteForceLockerAuthenticationFactory : AuthenticatorFactory {

    companion object {
        private const val PROVIDER_ID = "brute_force_locker"
        private val logger = Logger.getLogger(BruteForceLockerAuthenticationFactory::class.java)
    }

    override fun create(session: KeycloakSession?): Authenticator {
        return BruteForceLockerAuthentication()
    }

    override fun init(config: Config.Scope?) {
        logger.info(">>>> INIT >>>>")
    }

    override fun postInit(sessionFactory: KeycloakSessionFactory) {
        logger.info(">>>> POST INIT >>>>")
    }

    override fun close() {
        logger.info(">>>> CLOSE >>>>")
    }

    override fun getId(): String {
        return PROVIDER_ID
    }

    override fun getDisplayType(): String = "Brute Force Locker"
    override fun getHelpText(): String = "Checkout login failures count"
    override fun getReferenceCategory(): String = "blocker"

    override fun isConfigurable(): Boolean = true
    override fun isUserSetupAllowed(): Boolean = true

    override fun getRequirementChoices(): Array<out AuthenticationExecutionModel.Requirement?>? {
        return ConfigurableAuthenticatorFactory.REQUIREMENT_CHOICES
    }

    override fun getConfigProperties(): List<ProviderConfigProperty?>? {
        return ProviderConfigurationBuilder.create()
            .property()
            .name(BRUTE_FORCE_SWITCH)
            .label("Brute force switch")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .helpText("Если \"ON\" - будет выполняться проверка на количество ошибок входа")
            .defaultValue(true)
            .add()

            .property()
            .name(BRUTE_FORCE_COUNT)
            .label("Maximum login error count")
            .type(ProviderConfigProperty.INTEGER_TYPE)
            .helpText("После скольких ошибок входа, блокировать пользователя")
            .defaultValue(5)
            .add()

            .property()
            .name(BRUTE_FORCE_BLOCK_MINUTES)
            .label("Maximum period of blocking in minutes")
            .type(ProviderConfigProperty.INTEGER_TYPE)
            .helpText("Максимальное время, на которое блокируется пользователь")
            .defaultValue(5)
            .add()

            .property()
            .name(BRUTE_FORCE_RESET_MINUTES)
            .label("Reset time in minutes")
            .type(ProviderConfigProperty.INTEGER_TYPE)
            .helpText("Время в минутах, в течение которого сбрасываются разовые ошибки")
            .defaultValue(120)

            .add()
            .build()
            .also {
                logger.info("Initialize configuration properties :: Brute Force login failures logic")
            }
    }


}