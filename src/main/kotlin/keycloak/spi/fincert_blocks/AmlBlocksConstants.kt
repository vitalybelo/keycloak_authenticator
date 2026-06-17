package keycloak.spi.fincert_blocks

class AmlBlocksConstants {

    companion object {

        const val AML_BLOCKS_ENABLED_KEY = "enabled"
        const val AML_BLOCKS_ENABLED_VALUE = true

        const val AML_BLOCKS_URL_AML_ADAPTER_KEY = "url"
        const val AML_BLOCKS_URL_AML_ADAPTER_VALUE = "http://ms-aml-adp.uciam.svc:80/aml/customers/blocks"

        const val AML_BLOCKS_REQUEST_PARAMETER_KEY = "parameter"
        const val AML_BLOCKS_REQUEST_PARAMETER_VALUE = "abscustId"

        const val AML_BLOCKS_MOCK_ENABLED_KEY = "mock_enabled"
        const val AML_BLOCKS_MOCK_ENABLED_VALUE = false

        const val AML_BLOCKS_MOCK_BEHAVIOUR_KEY = "mock_behaviour"
        const val AML_BLOCKS_MOCK_BEHAVIOUR_DEFAULT = "RANDOM"
        val AML_BLOCKS_MOCK_BEHAVIOUR_VALUE = mutableListOf("FA", "FB", AML_BLOCKS_MOCK_BEHAVIOUR_DEFAULT)

        const val AML_BLOCKS_TIMEOUT_KEY = "timeout"
        const val AML_BLOCKS_TIMEOUT_VALUE = 60L

    }
}