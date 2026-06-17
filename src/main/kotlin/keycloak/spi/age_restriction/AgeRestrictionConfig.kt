package keycloak.spi.age_restriction

import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext
import java.time.format.DateTimeFormatter


data class AgeRestrictionConfig(

    val isEnabled: Boolean,
    val attributeName: String,
    val birthDateFormat: String,
    val ageRestrictionLimit: Int,
    val dateTimeFormatter: DateTimeFormatter

) {
    companion object {

        private val logger = Logger.getLogger(AgeRestrictionConfig::class.java)

        fun init(context: AuthenticationFlowContext): AgeRestrictionConfig {

            val configModel = context.authenticatorConfig
            val authenticatorConfig = configModel?.config

            val birthDateFormat = authenticatorConfig?.get(AgeConstants.AGE_RESTRICTION_BIRTH_DATE_FORMAT_KEY)
                ?: AgeConstants.AGE_RESTRICTION_BIRTH_DATE_FORMAT_VALUE

            val ageRestrictionConfig = AgeRestrictionConfig(
                isEnabled = authenticatorConfig?.get(AgeConstants.AGE_RESTRICTION_ENABLED_KEY)?.toBooleanStrictOrNull()
                    ?: AgeConstants.AGE_RESTRICTION_ENABLED_VALUE,
                attributeName = authenticatorConfig?.get(AgeConstants.AGE_RESTRICTION_BIRTH_DATE_ATTRIBUTE_KEY)
                    ?: AgeConstants.AGE_RESTRICTION_BIRTH_DATE_ATTRIBUTE_VALUE,
                birthDateFormat = birthDateFormat,
                ageRestrictionLimit = authenticatorConfig?.get(AgeConstants.AGE_RESTRICTION_LIMIT_KEY)?.toIntOrNull()
                    ?: AgeConstants.AGE_RESTRICTION_LIMIT_VALUE,
                dateTimeFormatter = DateTimeFormatter.ofPattern(birthDateFormat)
            )

            logger.debug("""AGE RESTRICTION config:
                | ------------------------------------------------------------
                | isEnabled: ${ageRestrictionConfig.isEnabled}
                | attributeName: ${ageRestrictionConfig.attributeName}
                | birthDateFormat: ${ageRestrictionConfig.birthDateFormat}
                | ageRestrictionLimit: ${ageRestrictionConfig.ageRestrictionLimit}
                | ------------------------------------------------------------
            """.trimIndent()
            )

            return ageRestrictionConfig
        }
    }

}