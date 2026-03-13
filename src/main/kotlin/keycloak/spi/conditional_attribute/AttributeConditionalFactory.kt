package keycloak.spi.conditional_attribute

import com.google.auto.service.AutoService
import keycloak.spi.constants.Constants
import org.jboss.logging.Logger
import org.keycloak.Config
import org.keycloak.authentication.AuthenticatorFactory
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory
import org.keycloak.models.AuthenticationExecutionModel.Requirement
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ProviderConfigurationBuilder

/**
 * Фабрика аутентификатора
 * @author Belotserkovskii Vitaly (c) 2025
 */
@AutoService(AuthenticatorFactory::class)
class AttributeConditionalFactory : ConditionalAuthenticatorFactory {

    companion object {
        private const val PROVIDER_ID = "check_attribute_condition"
        private val logger = Logger.getLogger(AttributeConditionalFactory::class.java)
        private val SINGLETON = AttributeConditional()
    }

    override fun getSingleton(): ConditionalAuthenticator {
        return SINGLETON
    }

    override fun getDisplayType(): String = "Condition - check user attribute"
    override fun isConfigurable(): Boolean = true
    override fun isUserSetupAllowed(): Boolean = false
    override fun getHelpText(): String = "Flow is executed only if the user attribute exists and has the expected one of defined values"

    override fun getRequirementChoices(): Array<Requirement?> {
        return arrayOf(Requirement.REQUIRED, Requirement.DISABLED)
    }

    override fun getConfigProperties(): List<ProviderConfigProperty?>? {

        return ProviderConfigurationBuilder.create()
            .property()
            .name(Constants.ATTRIBUTE_NAME)
            .label("Attribute name")
            .type(ProviderConfigProperty.STRING_TYPE)
            .helpText("Название атрибута для которого проводится проверка")
            .defaultValue("")
            .add()

            .property()
            .name(Constants.ATTRIBUTE_VALUES)
            .label("Attribute value list")
            .type(ProviderConfigProperty.MULTIVALUED_STRING_TYPE)
            .helpText("Значения атрибутов для которых будет работать условие")
            .defaultValue("")
            .add()

            .property()
            .name(Constants.ATTRIBUTE_GROUPS_KEY)
            .label("Include groups attributes")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .helpText("Если установлено \"ON\" - будем искать еще совпадения в атрибутах групп, которые назначены пользователю")
            .defaultValue(Constants.ATTRIBUTE_GROUPS_VALUE)
            .add()

            .property()
            .name(Constants.NEGATE_ENABLED_KEY)
            .label("Negate output")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .helpText("Если установлено \"ON\" - в случае несовпадения условий, результат будет TRUE")
            .defaultValue(Constants.NEGATE_ENABLED_VALUE)

            .add().build()
            .also {
                logger.info("Initialize configuration properties :: Condition - check user attribute")
            }
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




}