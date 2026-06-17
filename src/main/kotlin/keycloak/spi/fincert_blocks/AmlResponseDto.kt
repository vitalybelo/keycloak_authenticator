package keycloak.spi.fincert_blocks

import com.fasterxml.jackson.annotation.JsonIgnoreProperties

@JsonIgnoreProperties(ignoreUnknown = true)
class AmlResponseDto {
    var blocks: AmlFincertDto? = null
}

@JsonIgnoreProperties(ignoreUnknown = true)
class AmlFincertDto(
    var fincert: String? = null
)