package keycloak.spi.conditional_attribute

import org.jboss.logging.Logger
import keycloak.spi.constants.Constants
import org.keycloak.authentication.AuthenticationFlowContext


data class AttributeAuthConfig(

    val attributeName: String,
    val attributeValues: Set<String>,
    val isGroups: Boolean,
    val isNegate: Boolean
) {

    companion object {
        private val logger = Logger.getLogger(AttributeAuthConfig::class.java)

        fun init(context: AuthenticationFlowContext): AttributeAuthConfig {

            val config = context.authenticatorConfig
            val attributeName = config?.config[Constants.ATTRIBUTE_NAME] ?: Constants.ATTRIBUTE_ABSENT
            val attributeValues = config?.config[Constants.ATTRIBUTE_VALUES]?.split("##")?.toSet() ?: emptySet()
            val isGroups = config?.config?.get(Constants.ATTRIBUTE_GROUPS_KEY)?.toBooleanStrictOrNull() ?: Constants.ATTRIBUTE_GROUPS_VALUE
            val isNegate = config?.config[Constants.NEGATE_ENABLED_KEY]?.toBooleanStrictOrNull() ?: Constants.NEGATE_ENABLED_VALUE

            logger.debug(""">>>>
                | Attribute Authentication Config:
                | ----------------------------------------------------
                | attribute_name: $attributeName
                | attribute_values: $attributeValues
                | is_groups: $isGroups
                | is_negate: $isNegate
            """.trimIndent()
            )
            return AttributeAuthConfig(
                attributeName = attributeName,
                attributeValues = attributeValues,
                isGroups = isGroups,
                isNegate = isNegate
            )
        }
    }

    fun isNullOrEmpty(): Boolean = (attributeName == Constants.ATTRIBUTE_ABSENT || attributeValues.isEmpty())

}
