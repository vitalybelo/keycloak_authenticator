package keycloak.spi.enter_time_logics

import keycloak.spi.constants.Constants.Companion.ENTER_TIME_ATTRIBUTE
import keycloak.spi.constants.Constants.Companion.ENTER_TIME_FORMATTER
import keycloak.spi.constants.Constants.Companion.ENTER_TIME_PERIOD
import keycloak.spi.constants.Constants.Companion.ENTER_TIME_SWITCH
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.Authenticator
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import java.time.Instant
import java.time.ZonedDateTime
import javax.management.timer.Timer
import java.time.Duration


class EnterTimeAuthentication() : Authenticator {

    companion object {
        private val logger = Logger.getLogger(EnterTimeAuthentication::class.java)
    }

    override fun authenticate(context: AuthenticationFlowContext?) {

        if (context != null) {

            val user = context.user
            val config = context.authenticatorConfig
            val isEnterTimeLogic = config?.config[ENTER_TIME_SWITCH]?.toBoolean() ?: false
            val deadLinePeriodInDays = config?.config[ENTER_TIME_PERIOD]?.toInt()

            logger.info(">>>> User = ${user.username}")
            logger.info(">>>> Enter Time Switch = $isEnterTimeLogic")
            logger.info(">>>> Enter Time Period = $deadLinePeriodInDays")

            if (isEnterTimeLogic && deadLinePeriodInDays != null) {

                // параметры аутентификатора заданы, будем проверять логику для смены пароля
                user.getFirstAttribute(ENTER_TIME_ATTRIBUTE)?.let { enterTimeString ->

                    val previousEnterMillis =
                        ZonedDateTime.parse(enterTimeString, ENTER_TIME_FORMATTER).toInstant().toEpochMilli()
                    val instantEnterMillis = Instant.now().toEpochMilli()
                    val passedPeriodInMillis = instantEnterMillis - previousEnterMillis
                    val deadLinePeriodInMillis = deadLinePeriodInDays * Timer.ONE_DAY
                    val duration = Duration.ofMillis(passedPeriodInMillis)
                    val days = duration.toDays()
                    val hours = duration.minusDays(days).toHours()
                    val minutes = duration.minusDays(days)
                        .minusHours(hours).toMinutes()
                    val seconds = duration.minusDays(days)
                        .minusHours(hours).minusMinutes(minutes).toSeconds()

                    logger.info(">>>> From last login " +
                            "passed = $days days, $hours hours, $minutes minutes, $seconds seconds")

                    if (passedPeriodInMillis > deadLinePeriodInMillis) {

                        logger.warn(">>>> From last login passed more than = $deadLinePeriodInDays")
                        user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD)
                    }
                }
            }

            // время последнего входа устанавливаем вне зависимости от переключателя логики, всегда
            val enterIsoTime = ENTER_TIME_FORMATTER.format(ZonedDateTime.now())
            user.setSingleAttribute(
                ENTER_TIME_ATTRIBUTE,
                enterIsoTime
            )
            val enterTime: String? = user.getFirstAttribute(ENTER_TIME_ATTRIBUTE)
            logger.info(">>>> Updated enter time = $enterTime")

            context.success()
        }
    }


    override fun action(context: AuthenticationFlowContext?) {
    }

    override fun requiresUser(): Boolean {
        return true
    }

    override fun configuredFor(
        session: KeycloakSession?,
        realm: RealmModel?,
        user: UserModel?
    ): Boolean {
        return true
    }

    override fun setRequiredActions(
        session: KeycloakSession?,
        realm: RealmModel?,
        user: UserModel?
    ) {
    }

    override fun close() {
    }

}