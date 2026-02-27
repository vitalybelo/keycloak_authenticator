package keycloak.spi.event_listener

import keycloak.spi.brute_force_locker.BruteForceLockerConfig
import org.jboss.logging.Logger
import java.io.Serializable
import java.util.concurrent.TimeUnit

data class LoginAttempt(

    val failures: Int = 0,
    val isBlocked: Boolean = false,
    val lastFailure: Long = System.currentTimeMillis(),

) : Serializable {

    companion object {
        private val logger = Logger.getLogger(LoginAttempt::class.java)
    }

    fun displayLoginAttempts() {

        logger.debug(""">>>>
            | Saved login errors attempts
            | ------------------------------------
            | failures = $failures
            | is blocked = $isBlocked
            | lastFailure = $lastFailure
            | ------------------------------------
            """.trimIndent()
        )
    }

    fun displayBlockedMessage(lockerConfig: BruteForceLockerConfig) {

        val totalInMillis = TimeUnit.MINUTES.toMillis(lockerConfig.blockDurationMinutes)
        val spentInMillis = System.currentTimeMillis() - lastFailure
        val remainder = totalInMillis - spentInMillis

        if (remainder > 0) {

            val minutes = TimeUnit.MILLISECONDS.toMinutes(remainder)
            val seconds = TimeUnit.MILLISECONDS.toSeconds(remainder) % 60
            val timeMessage = if (minutes > 0) {"$minutes мин. $seconds сек." } else { "$seconds сек." }

            logger.warn(">>>> User :: ${lockerConfig.username} temporally blocked at: $timeMessage")
        } else {
            logger.info(">>>> User :: ${lockerConfig.username} block passed")
        }
    }

}