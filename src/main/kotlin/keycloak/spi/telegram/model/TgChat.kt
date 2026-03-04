package keycloak.spi.telegram.model

import com.fasterxml.jackson.annotation.JsonIgnoreProperties

@JsonIgnoreProperties(ignoreUnknown = true)
data class TgChat(

    val id: Long
)
