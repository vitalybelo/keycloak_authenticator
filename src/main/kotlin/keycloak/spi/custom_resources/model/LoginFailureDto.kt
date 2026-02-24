package keycloak.spi.custom_resources.model

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import org.keycloak.models.UserLoginFailureModel

@JsonIgnoreProperties(ignoreUnknown = true)
data class LoginFailureDto(

    @JsonProperty("id") val id: String? = null,
    @JsonProperty("userId") val userId: String? = null,
    @JsonProperty("lastFailure") val lastFailure: Long? = null,
    @JsonProperty("numFailures") val numFailures: Int? = null,
    @JsonProperty("lastIPFailure") val lastIPFailure: String? = null,
    @JsonProperty("numTemporaryLockouts") val numTemporaryLockouts: Int? = null,
    @JsonProperty("failedLoginNotBefore") val failedLoginNotBefore: Int? = null

) {

    companion object {
        fun fromModel(model: UserLoginFailureModel): LoginFailureDto {
            return LoginFailureDto(
                id = model.id,
                userId = model.userId,
                lastFailure = model.lastFailure,
                numFailures = model.numFailures,
                lastIPFailure = model.lastIPFailure,
                numTemporaryLockouts = model.numTemporaryLockouts,
                failedLoginNotBefore = model.failedLoginNotBefore
            )
        }
    }
}