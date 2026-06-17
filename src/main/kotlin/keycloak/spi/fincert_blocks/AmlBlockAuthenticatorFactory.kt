package keycloak.spi.fincert_blocks

import org.jboss.logging.Logger
import org.keycloak.Config
import org.keycloak.authentication.Authenticator
import org.keycloak.authentication.AuthenticatorFactory
import org.keycloak.authentication.ConfigurableAuthenticatorFactory
import org.keycloak.models.AuthenticationExecutionModel.Requirement
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ProviderConfigurationBuilder


class AmlBlockAuthenticatorFactory : AuthenticatorFactory {

    companion object {
        private val logger = Logger.getLogger(AmlBlockAuthenticatorFactory::class.java.name)
        const val PROVIDER_ID: String = "aml-fincert-block-authenticator"
    }

    override fun getDisplayType(): String = "AML Fincert Customer Block"
    override fun getHelpText(): String = "Проверка блокировок клиента в микросервисе AML. Прерывает флоу при наличии блокировки fincert = FB."
    override fun getReferenceCategory(): String = "AML"
    override fun isConfigurable(): Boolean = true
    override fun isUserSetupAllowed(): Boolean = false
    override fun getRequirementChoices(): Array<Requirement?> = ConfigurableAuthenticatorFactory.REQUIREMENT_CHOICES


    override fun getConfigProperties(): MutableList<ProviderConfigProperty?> {

        return ProviderConfigurationBuilder.create()
            .property()
            .name(AmlBlocksConstants.AML_BLOCKS_ENABLED_KEY)
            .label("Aml blocks enabled")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .helpText("Если \"ON\" - будет выполняться проверка на блокировки пользователя по FINCERT")
            .defaultValue(AmlBlocksConstants.AML_BLOCKS_ENABLED_VALUE)
            .add()

            .property()
            .name(AmlBlocksConstants.AML_BLOCKS_URL_AML_ADAPTER_KEY)
            .label("AML adapter URL")
            .type(ProviderConfigProperty.STRING_TYPE)
            .helpText("Например: http://ms-aml-adp.uciam.svc:80/aml/customers/blocks")
            .defaultValue(AmlBlocksConstants.AML_BLOCKS_URL_AML_ADAPTER_VALUE)
            .add()

            .property()
            .name(AmlBlocksConstants.AML_BLOCKS_REQUEST_PARAMETER_KEY)
            .label("AML adapter parameter")
            .type(ProviderConfigProperty.STRING_TYPE)
            .helpText("Параметр запроса в aml адаптер, для получения статуса блокировки пользователя по Финцерт")
            .defaultValue(AmlBlocksConstants.AML_BLOCKS_REQUEST_PARAMETER_VALUE)
            .add()

            .property()
            .name(AmlBlocksConstants.AML_BLOCKS_TIMEOUT_KEY)
            .label("Request timeout")
            .type(ProviderConfigProperty.INTEGER_TYPE)
            .helpText("Таум-аут запроса в aml адаптер")
            .defaultValue(AmlBlocksConstants.AML_BLOCKS_TIMEOUT_VALUE)
            .add()

            .property()
            .name(AmlBlocksConstants.AML_BLOCKS_MOCK_ENABLED_KEY)
            .label("AML mock enabled")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .helpText("Если \"ON\" - будет работать режим симуляции")
            .defaultValue(AmlBlocksConstants.AML_BLOCKS_MOCK_ENABLED_VALUE)
            .add()

            .property()
            .name(AmlBlocksConstants.AML_BLOCKS_MOCK_BEHAVIOUR_KEY)
            .label("AML mock behaviour")
            .type(ProviderConfigProperty.LIST_TYPE)
            .helpText("Поведение симуляции: FA (всегда нет блокировки), FB (всегда есть блокировка), RANDOM (случайно)")
            .options(AmlBlocksConstants.AML_BLOCKS_MOCK_BEHAVIOUR_VALUE)
            .add()

            .build()
            .also {
                logger.info(">>>> PROPERTIES :: Initialize configuration properties :: Aml Blocks Authenticator")
            }
    }


    override fun create(session: KeycloakSession?): Authenticator = AmlBlockAuthenticator()

    override fun init(config: Config.Scope?) { logger.info(">>>> INIT :: AML Block Authenticator") }
    override fun postInit(factory: KeycloakSessionFactory?) { logger.info(">>>> POST INIT :: AML Block Authenticator") }
    override fun close() { logger.info(">>>> CLOSE :: AML Block Authenticator") }
    override fun getId(): String = PROVIDER_ID

}