package keycloak.spi.fincert_blocks

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.AuthenticationFlowError
import org.keycloak.authentication.Authenticator
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.http.HttpTimeoutException
import java.nio.charset.StandardCharsets
import java.time.Duration


@Suppress("DuplicatedCode")
class AmlBlockAuthenticator : Authenticator {

    companion object {

        private val mapper = jacksonObjectMapper()
        private val logger = Logger.getLogger(AmlBlockAuthenticator::class.java.name)
    }


    override fun authenticate(context: AuthenticationFlowContext) {

        logger.info("AML Blocks Authenticator started")
        val config = AmlBlocksConfig.init(context)

        // уточняем - нужно ли выполнять проверки
        if (!config.isEnabled) {
            logger.info("AML Blocks Authenticator disabled :: stop processing")
            context.success()
            return
        }

        // проверяем имеется ли у нас пользователь в контексте потока
        val user = context.user
        if (user == null) {
            logger.warn("No user found in flow context")
            sendCustomError(
                context = context,
                flowError = AuthenticationFlowError.UNKNOWN_USER,
                status = Response.Status.UNAUTHORIZED,
                error = "unknown_user",
                errorDescription = "User not found in authentication context"
            )
            return
        }
        val username = user.username ?: "unknown_user"

        // Пытаемся получить идентификатор пользователя для запроса в aml adapter
        // Если идентификатора нет, логично считать проверку не пройденной, по ТЗ прерываем флоу.
        val parameter = config.amlAdapterParam
        val userConfiguredId = user.getFirstAttribute(parameter)
        if (userConfiguredId.isNullOrBlank()) {
            logger.warn("Request parameter = [$parameter] not found in attributes")
            sendCustomError(
                context = context,
                flowError = AuthenticationFlowError.INVALID_USER,
                status = Response.Status.NOT_FOUND,
                error = "invalid_parameter",
                errorDescription = "Request parameter = [$parameter] not found for user: [$username] :: stop"
            )
            return
        } else {
            logger.info("Request parameter $parameter = [$userConfiguredId] found in attributes for user: [$username]")
        }

        // если режим симуляции включен, продолжаем обработку в режиме симуляции
        if (config.isMockEnabled) {
            logger.info("AML Blocks Simulation enabled with mode = ${config.mockBehaviour}")
            handleMock(context, config.mockBehaviour)
            return
        }

        logger.info("Http request to AML adapter started")
        try {
            val client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(config.amlAdapterTimeout))
                .build()

            val finalUrl = StringBuilder(config.amlAdapterURL)
                .append("?").append(config.amlAdapterParam).append("=")
                .append(URLEncoder.encode(userConfiguredId, StandardCharsets.UTF_8)).toString()

            logger.info("Request URL = $finalUrl")
            val request = HttpRequest.newBuilder()
                .GET()
                .uri(URI.create(finalUrl))
                .timeout(Duration.ofSeconds(config.amlAdapterTimeout))
                .build()

            val response =
                client.send(request, HttpResponse.BodyHandlers.ofString())

            if (response.statusCode() == 200) {

                val body = response.body()
                logger.info("Response body from AML adapter: $body")
                if (body.isNullOrBlank()) {
                    logger.warn("Response body from aml adapter is empty")
                    failWithBlocked(context)
                    return
                }

                val root = mapper.readTree(body)
                val blocks = root.path("blocks")

                if (blocks.isObject && "FB" == blocks.path("fincert").asText()) {
                    logger.warn("Received fincert blocks = FB from aml adapter")
                    failWithBlocked(context)
                } else {
                    context.success()
                }
            } else {
                // Сервис ответил не 200 - по условиям считаем, что проверка не пройдена
                logger.warn("Received response status = ${response.statusCode()} from aml adapter")
                failWithBlocked(context)
            }
        } catch (ex: HttpTimeoutException) {
            logger.error("AML request timeout = ${config.amlAdapterTimeout} occurred", ex)
            failWithBlocked(context)
        } catch (ex: Exception) {
            logger.error("Unexpected AML request network error occurred", ex)
            failWithBlocked(context)
        }
    }

    /**
     * Реализует режим симуляции для аутентификатора aml блокировки по Финцерт
     * @param context контекст потока регистрации/аутентификации
     * @param behavior режим выполнения симуляции
     */
    private fun handleMock(
        context: AuthenticationFlowContext,
        behavior: String
    ) {

        when (behavior) {
            "FB" -> {
                logger.info("Simulate fincert = FB exactly")
                failWithBlocked(context)
            }
            "RANDOM" -> if (Math.random() < 0.5) {
                logger.info("Simulate fincert = RANDOM -> FB")
                failWithBlocked(context)
            } else {
                logger.info("Simulate fincert = RANDOM -> FA")
                context.success()
            }
            "FA" -> {
                logger.info("Simulate fincert = FA exactly")
                context.success()
            }
            else -> context.success()
        }
    }

    /**
     * Формируем HTTP 400 ответ для MBPI с информацией о блокировке пользователя и завершаем выполнение
     * @param context контекст потока регистрации/аутентификации
     */
    private fun failWithBlocked(context: AuthenticationFlowContext) {

        logger.info("Fail with AML blocking")
        sendCustomError(
            context = context,
            flowError = AuthenticationFlowError.ACCESS_DENIED,
            status = Response.Status.FORBIDDEN,
            error = "fincert_blocked",
            errorDescription = "user is blocked"
        )
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


    override fun action(context: AuthenticationFlowContext?) {
        // Не используется в данном сценарии, так как нет формы для сабмита
    }
    override fun requiresUser(): Boolean = false
    override fun configuredFor(session: KeycloakSession?, realm: RealmModel?, user: UserModel?): Boolean = true
    override fun setRequiredActions(session: KeycloakSession?, realm: RealmModel?, user: UserModel?) {}
    override fun close() {}

}