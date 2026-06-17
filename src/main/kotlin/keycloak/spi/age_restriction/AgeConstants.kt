package keycloak.spi.age_restriction

class AgeConstants {

    companion object {

        const val AGE_RESTRICTION_ENABLED_KEY = "age_restriction_enabled"
        const val AGE_RESTRICTION_ENABLED_VALUE = true

        const val AGE_RESTRICTION_BIRTH_DATE_ATTRIBUTE_KEY = "birth_date_attribute"
        const val AGE_RESTRICTION_BIRTH_DATE_ATTRIBUTE_VALUE = "birthDate"

        const val AGE_RESTRICTION_BIRTH_DATE_FORMAT_KEY = "birth_date_format"
        const val AGE_RESTRICTION_BIRTH_DATE_FORMAT_VALUE = "yyyy-MM-dd"

        const val AGE_RESTRICTION_LIMIT_KEY = "upper_age_limit"
        const val AGE_RESTRICTION_LIMIT_VALUE = 18

    }
}