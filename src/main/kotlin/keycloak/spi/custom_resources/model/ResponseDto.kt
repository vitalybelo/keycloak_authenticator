package keycloak.spi.custom_resources.model

import com.fasterxml.jackson.annotation.JsonInclude

@JsonInclude(JsonInclude.Include.NON_NULL)
data class ResponseDto(

    val status: String,
    val message: String,
    val body: Any? = null

) {
    companion object {

        fun success(
            message: String,
            body: Any? = null
        ): ResponseDto {

            return ResponseDto(
                status = "success",
                message = message,
                body = body
            )
        }

        fun error(message: String): ResponseDto {

            return ResponseDto(
                status = "error",
                message = message
            )
        }

    }
}