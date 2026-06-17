@file:Suppress("DuplicatedCode")

package keycloak.spi.age_restriction

import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.AuthenticationFlowError
import org.keycloak.authentication.Authenticator
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import java.time.LocalDate
import java.time.Period
import java.time.format.DateTimeParseException

class AgeRestrictionAuthenticator : Authenticator {

    companion object {
        private val logger = Logger.getLogger(AgeRestrictionAuthenticator::class.java.name)
    }

    override fun authenticate(context: AuthenticationFlowContext) {

        logger.debug("Age Restriction Authentication flow started")
        val config = AgeRestrictionConfig.init(context)

        // проверка флага Enabled - если он отключен, выполнение проверки на возраст не требуется
        if (!config.isEnabled) {
            logger.debug("Age restriction checkout disabled")
            context.success()
            return
        }

        // проверяем имеется ли у нас пользователь в контексте потока
        val user = context.user
        if (user == null) {
            logger.debug("No user found in flow context")
            sendCustomError(
                context = context,
                flowError = AuthenticationFlowError.UNKNOWN_USER,
                status = Response.Status.UNAUTHORIZED,
                error = "unknown_user",
                errorDescription = "User not found in authentication context"
            )
            return
        }

        // получение даты рождения пользователя, если даты нет - прерываем поток с ошибкой
        val birthDateString = user.getFirstAttribute(config.attributeName)
        if (birthDateString.isNullOrBlank()) {
            sendCustomError(
                context = context,
                flowError = AuthenticationFlowError.INVALID_USER,
                status = Response.Status.NOT_FOUND,
                error = "invalid_birth_date",
                errorDescription = "User birth date attribute '${config.attributeName}' is missing or empty."
            )
            return
        }

        // вычисление возраста пользователя и проверка на взрослость,
        // при ошибке или излишней молодости - прерываем поток регистрации/аутентификации
        try {
            val birthDate = LocalDate.parse(birthDateString, config.dateTimeFormatter)
            val age = Period.between(birthDate, LocalDate.now()).years

            if (age >= config.ageRestrictionLimit) {
                logger.debug("No age restrictions found")
                context.success()
            } else {
                logger.debug("Age restriction under :: ${config.ageRestrictionLimit} years found")
                sendCustomError(
                    context = context,
                    flowError = AuthenticationFlowError.ACCESS_DENIED,
                    status = Response.Status.FORBIDDEN,
                    error = "invalid_age",
                    errorDescription = "User age not allowed (actual age = $age years)"
                )
            }
        } catch (ex: DateTimeParseException) {
            logger.error("Failed to parse birth date $birthDateString, message = ${ex.message}, cause = ${ex.cause}")
            sendCustomError(
                context = context,
                flowError = AuthenticationFlowError.INVALID_USER,
                status = Response.Status.BAD_REQUEST,
                error = "invalid_birth_date_format",
                errorDescription = "Failed to parse user birth date. Expected format: ${config.birthDateFormat}"
            )
        }
    }

    /**
     * Формирует кастомный ответ клиенту с формированием json
     * @param context контекст потока аутентификации
     * @param flowError тип ошибки потока аутентификации
     * @param status статус возвращаемый клиенту
     * @param error заголовок описания ошибки
     * @param errorDescription описание ошибки
     */
    private fun sendCustomError(
        context: AuthenticationFlowContext,
        flowError: AuthenticationFlowError,
        status: Response.Status,
        error: String,
        errorDescription: String
    ) {
        val response = Response
            .status(status)
            .type(MediaType.APPLICATION_JSON_TYPE)
            .entity(
                mapOf(
                    "error" to error,
                    "error_description" to errorDescription
                )
            )
            .build()

        context.failure(flowError, response)
    }


    override fun action(context: AuthenticationFlowContext) {
        // Оставляем пустым
    }

    override fun requiresUser(): Boolean = true
    override fun configuredFor(session: KeycloakSession, realm: RealmModel, user: UserModel): Boolean = true
    override fun setRequiredActions(session: KeycloakSession, realm: RealmModel, user: UserModel) {}
    override fun close() {}


}