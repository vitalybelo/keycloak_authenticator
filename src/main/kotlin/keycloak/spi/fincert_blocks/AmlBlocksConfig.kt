package keycloak.spi.fincert_blocks

import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext

data class AmlBlocksConfig(

    val isEnabled: Boolean,
    val amlAdapterURL: String,
    val amlAdapterParam: String,
    val amlAdapterTimeout: Long,
    val isMockEnabled: Boolean,
    val mockBehaviour: String

) {

    companion object {

        private val logger = Logger.getLogger(AmlBlocksConfig::class.java.name)

        fun init(context: AuthenticationFlowContext): AmlBlocksConfig {

            val configModel = context.authenticatorConfig
            val config = configModel?.config

            val amlBlocksConfig = AmlBlocksConfig(
                isEnabled = config?.get(AmlBlocksConstants.AML_BLOCKS_ENABLED_KEY)?.toBooleanStrictOrNull()
                    ?: AmlBlocksConstants.AML_BLOCKS_ENABLED_VALUE,
                amlAdapterURL = config?.get(AmlBlocksConstants.AML_BLOCKS_URL_AML_ADAPTER_KEY)
                    ?: AmlBlocksConstants.AML_BLOCKS_URL_AML_ADAPTER_VALUE,
                amlAdapterParam = config?.get(AmlBlocksConstants.AML_BLOCKS_REQUEST_PARAMETER_KEY)
                    ?: AmlBlocksConstants.AML_BLOCKS_REQUEST_PARAMETER_VALUE,
                amlAdapterTimeout = config?.get(AmlBlocksConstants.AML_BLOCKS_TIMEOUT_KEY)?.toLongOrNull()
                    ?: AmlBlocksConstants.AML_BLOCKS_TIMEOUT_VALUE,
                isMockEnabled = config?.get(AmlBlocksConstants.AML_BLOCKS_MOCK_ENABLED_KEY)?.toBooleanStrictOrNull()
                    ?: AmlBlocksConstants.AML_BLOCKS_MOCK_ENABLED_VALUE,
                mockBehaviour = config?.get(AmlBlocksConstants.AML_BLOCKS_MOCK_BEHAVIOUR_KEY)
                    ?: AmlBlocksConstants.AML_BLOCKS_MOCK_BEHAVIOUR_DEFAULT
            )

            logger.debug("""AML BLOCKS config:
                | ------------------------------------------------------------
                | isEnabled = ${amlBlocksConfig.isEnabled}
                | amlAdapterURL = ${amlBlocksConfig.amlAdapterURL}
                | amlAdapterParam = ${amlBlocksConfig.amlAdapterParam}
                | amlAdapterTimeout = ${amlBlocksConfig.amlAdapterTimeout}
                | isMockEnabled = ${amlBlocksConfig.isMockEnabled}
                | mockBehaviour = ${amlBlocksConfig.mockBehaviour}
                | ------------------------------------------------------------
            """.trimIndent()
            )
            return amlBlocksConfig
        }
    }
}