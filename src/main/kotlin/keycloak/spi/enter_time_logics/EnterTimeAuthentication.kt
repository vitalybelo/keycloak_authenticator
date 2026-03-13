package keycloak.spi.enter_time_logics

import keycloak.spi.constants.Constants
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.Authenticator
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import java.time.Instant
import java.time.ZonedDateTime
import java.time.Duration
import java.util.concurrent.TimeUnit


class EnterTimeAuthentication : Authenticator {

    companion object {
        private val logger = Logger.getLogger(EnterTimeAuthentication::class.java)
    }


    override fun authenticate(context: AuthenticationFlowContext?) {

        if (context != null) {

            val user = context.user ?: return
            val config = context.authenticatorConfig
            val isEnterTimeLogicOn = config?.config[Constants.ENTER_TIME_SWITCH_KEY]?.toBoolean() ?: Constants.ENTER_TIME_SWITCH_VALUE
            val requireActionInDays = config?.config[Constants.ENTER_TIME_PERIOD_KEY]?.toLong() ?: Constants.ENTER_TIME_PERIOD_VALUE

            logger.debug(""">>>>
                | Username: ${user.username}
                | Enter time switch = $isEnterTimeLogicOn
                | Enter time require action in days = $requireActionInDays
            """.trimIndent())

            if (isEnterTimeLogicOn) {
                // параметры аутентификатора заданы, будем проверять логику для смены пароля
                user.getFirstAttribute(Constants.ENTER_TIME_ATTRIBUTE)?.let { enterTimeString ->

                    try {
                        val lastEnterInMillis = ZonedDateTime
                            .parse(enterTimeString, Constants.ENTER_TIME_FORMATTER).toInstant().toEpochMilli()
                        val currentEnterInMillis = Instant.now().toEpochMilli()
                        val idlePeriodInMillis = currentEnterInMillis - lastEnterInMillis

                        val duration = Duration.ofMillis(idlePeriodInMillis)
                        val days = duration.toDays()
                        val hours = duration.toHoursPart()
                        val minutes = duration.toMinutesPart()
                        val seconds = duration.toSecondsPart()

                        logger.debug(""">>>>
                            | >>>> From user = ${user.username} last login passed:
                            | Days = $days
                            | Hours = $hours
                            | Minutes = $minutes
                            | Seconds = $seconds
                        """.trimIndent()
                        )

                        if (idlePeriodInMillis > TimeUnit.DAYS.toMillis(requireActionInDays)) {
                            logger.warn(">>>> Add required action to change password for user ${user.username}")
                            user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD)
                        }
                    } catch (ex: Exception) {
                        logger.error(">>>> Exception message : ${ex.message}, cause: ${ex.cause}")
                    }
                }
            }

            // время последнего входа устанавливаем вне зависимости от переключателя логики, всегда
            val enterIsoTime = Constants.ENTER_TIME_FORMATTER.format(ZonedDateTime.now())
            user.setSingleAttribute(
                Constants.ENTER_TIME_ATTRIBUTE,
                enterIsoTime
            )
            val enterTime: String? = user.getFirstAttribute(Constants.ENTER_TIME_ATTRIBUTE)
            logger.info(">>>> Updated enter time = $enterTime")

            context.success()
        }
    }


    override fun action(context: AuthenticationFlowContext?) {}
    override fun requiresUser(): Boolean = true
    override fun configuredFor(session: KeycloakSession?, realm: RealmModel?, user: UserModel?): Boolean = true
    override fun setRequiredActions(session: KeycloakSession?, realm: RealmModel?, user: UserModel?) {}
    override fun close() {}

}