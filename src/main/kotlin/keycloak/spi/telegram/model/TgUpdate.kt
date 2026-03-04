package keycloak.spi.telegram.model

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty

@JsonIgnoreProperties(ignoreUnknown = true)
data class TgUpdate(

    @JsonProperty("update_id") val updateId: Long,
    @JsonProperty("message") val message: TgMessage?
)
