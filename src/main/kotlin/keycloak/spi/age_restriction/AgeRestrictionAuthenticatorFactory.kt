package keycloak.spi.age_restriction

import org.jboss.logging.Logger
import org.keycloak.Config
import org.keycloak.authentication.Authenticator
import org.keycloak.authentication.AuthenticatorFactory
import org.keycloak.models.AuthenticationExecutionModel.Requirement
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ProviderConfigurationBuilder


class AgeRestrictionAuthenticatorFactory : AuthenticatorFactory {

    companion object {

        const val PROVIDER_ID: String = "age-restriction-authenticator"
        private val logger = Logger.getLogger(AgeRestrictionAuthenticatorFactory::class.java)
        private val SINGLETON = AgeRestrictionAuthenticator()
    }

    override fun getDisplayType(): String = "Age Restriction by birthDate"
    override fun getReferenceCategory(): String = "Age validation"
    override fun isConfigurable(): Boolean = true
    override fun isUserSetupAllowed(): Boolean = false
    override fun getHelpText(): String = "Block users who are younger than the configured age limit."

    override fun getRequirementChoices(): Array<Requirement?> {
        return arrayOf(
            Requirement.REQUIRED,
            Requirement.DISABLED
        )
    }

    override fun getConfigProperties(): MutableList<ProviderConfigProperty?> {

        return ProviderConfigurationBuilder.create()
            .property()
            .name(AgeConstants.AGE_RESTRICTION_ENABLED_KEY)
            .label("Age restriction enabled")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .helpText("Если \"ON\" - будет выполняться проверка на возраст по заданному параметру - лимит возраста, ниже которого регистрация запрещена.")
            .defaultValue(AgeConstants.AGE_RESTRICTION_ENABLED_VALUE)
            .add()

            .property()
            .name(AgeConstants.AGE_RESTRICTION_BIRTH_DATE_ATTRIBUTE_KEY)
            .label("User birth date attribute")
            .type(ProviderConfigProperty.STRING_TYPE)
            .helpText("Название атрибута хранящего дату рождения пользователя")
            .defaultValue(AgeConstants.AGE_RESTRICTION_BIRTH_DATE_ATTRIBUTE_VALUE)
            .add()

            .property()
            .name(AgeConstants.AGE_RESTRICTION_BIRTH_DATE_FORMAT_KEY)
            .label("User birth date format")
            .type(ProviderConfigProperty.STRING_TYPE)
            .helpText("Формат даты, в котором атрибут хранит дату дня рождения пользователя")
            .defaultValue(AgeConstants.AGE_RESTRICTION_BIRTH_DATE_FORMAT_VALUE)
            .add()

            .property()
            .name(AgeConstants.AGE_RESTRICTION_LIMIT_KEY)
            .label("Upper age limit")
            .type(ProviderConfigProperty.STRING_TYPE)
            .helpText("Возраст, ниже которого регистрация пользователя будет запрещена")
            .defaultValue(AgeConstants.AGE_RESTRICTION_LIMIT_VALUE)
            .add()

            .build()
            .also {
                logger.info(">>>> PROPERTIES :: Initialize configuration properties :: Age Restriction Authenticator")
            }
    }

    override fun create(session: KeycloakSession?): Authenticator {
        logger.debug(">>>> Creating Age Restriction Authenticator")
        return SINGLETON
    }

    override fun init(config: Config.Scope?) {
        logger.debug(">>>> INIT :: Age Restriction Authenticator")
    }

    override fun postInit(factory: KeycloakSessionFactory?) {
        logger.debug(">>>> POST INIT :: Age Restriction Authenticator")
    }

    override fun close() {
        logger.debug(">>>> CLOSE :: Age Restriction Authenticator")
    }

    override fun getId(): String {
        return PROVIDER_ID
    }

}