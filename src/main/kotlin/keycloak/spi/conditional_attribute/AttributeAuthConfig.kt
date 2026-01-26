package keycloak.spi.conditional_attribute

import org.jboss.logging.Logger
import keycloak.spi.constants.Constants
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.models.AuthenticatorConfigModel
import kotlin.text.toBoolean


data class AttributeAuthConfig(

    var attributeName: String? = null,
    var attributeValues: Set<String>? = null,
    var isGroups: Boolean? = null,
    var isNative: Boolean? = null,

) {

    companion object {
        private val logger = Logger.getLogger(AttributeAuthConfig::class.java)
    }

    constructor(context: AuthenticationFlowContext): this() {

        val config: AuthenticatorConfigModel? = context.authenticatorConfig

        attributeName = config?.config[Constants.ATTRIBUTE_NAME]
        attributeValues = config?.config[Constants.ATTRIBUTE_VALUES]?.split("##")?.toSet()
        isGroups = config?.config[Constants.ATTRIBUTE_GROUPS]?.toBoolean() ?: false
        isNative = config?.config[Constants.NATIVE_ENABLED]?.toBoolean() ?: false

        logger.info(">>>> Username name: ${context.user?.username}")
        logger.info(">>>> Attribute name = $attributeName")
        logger.info(">>>> Attribute values allowed = ${attributeValues.toString()}")
        logger.info(">>>> Attribute groups = $isGroups")
        logger.info(">>>> Native output = $isNative")
    }

    fun isConfigNotPresented(): Boolean = (attributeName.isNullOrEmpty() || attributeValues.isNullOrEmpty())


}
