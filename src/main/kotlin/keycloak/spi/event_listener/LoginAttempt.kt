package keycloak.spi.event_listener

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import java.io.Serializable

@JsonIgnoreProperties(ignoreUnknown = true)
data class LoginAttempt(

    val failures: Int = 0,
    val isBlocked: Boolean = false,
    val unlockTime: Long? = null

) : Serializable