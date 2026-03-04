package keycloak.spi.telegram.model

import com.fasterxml.jackson.annotation.JsonIgnoreProperties

@JsonIgnoreProperties(ignoreUnknown = true)
data class TgResponse(

    val ok: Boolean,
    val result: List<TgUpdate>?
)