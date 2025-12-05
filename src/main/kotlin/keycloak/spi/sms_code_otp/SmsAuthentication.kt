package keycloak.spi.sms_code_otp

import jakarta.ws.rs.core.Response
import keycloak.spi.constants.Constants
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.AuthenticationFlowError
import org.keycloak.authentication.Authenticator
import org.keycloak.common.util.SecretGenerator
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import javax.management.timer.Timer


class SmsAuthentication() : Authenticator {

    companion object {
        private val logger = Logger.getLogger(SmsAuthentication::class.java)
        private const val TPL_CODE = "login-sms.ftl"
    }

    /**
     * Метод вызывается в начале работы шага аутентификации 2FA SMS Authentication
     * Задача метода, сформировать секретный код СМС и отправить пользователю, инициализировать
     * значение для проверки тайм-аута и передать эти параметры через AuthNotes в форму ввода кода СМС.
     * Однако физическая отправка SMS в данном коде отсутствует, но отмечено место где она должна быть.
     * После этого, метод формирует и вызывает UI ввода кода. Управление передается далее в action()
     *
     * @param context контекст потока аутентификации
     */
    override fun authenticate(context: AuthenticationFlowContext?) {

        if (isContextDisable(context)) {
            return
        }
        val config = context!!.authenticatorConfig
        val user = context.user

        val username = user?.username
        val isStubEnable = config?.config[Constants.SMS_STUB_SWITCH]?.toBoolean() ?: true
        val stubCodeLength = config?.config[Constants.SMS_CODE_LENGTH]?.toInt() ?: 4
        val stubCodeValue = config?.config[Constants.SMS_STUB_CODE] ?: "1111"
        val smsCodeTTL = config?.config[Constants.SMS_TTL]?.toLong() ?: 60

        logger.info(">>>> username = $username")
        logger.info(">>>> SMS stub switch = $isStubEnable")
        logger.info(">>>> SMS stub length = $stubCodeLength")
        logger.info(">>>> SMS stub code = $stubCodeValue")
        logger.info(">>>> Sms code TTL = $smsCodeTTL")

        try {
            challengeSmsForm(context, isStubEnable, stubCodeValue, stubCodeLength, smsCodeTTL, null)
            // больше тут делать нечего, далее управление будет передано в метод action()

        } catch (ex: Exception) {
            // предполагается, что выше нужно было выслать СМС, этот блок именно для этого
            context.failureChallenge(
                AuthenticationFlowError.INTERNAL_ERROR,
                context.form().setError("smsAuthSmsNotSent", ex.message)
                    .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR))
        }
    }

    /**
     * Метод вызывается после того, как пользователь вводит - код подтверждения 2FA
     * Метод извлекает из контекста запроса введенный пользователем параметр и сравнивает с требуемым.
     *
     * @param context контекст потока аутентификации
     */
    override fun action(context: AuthenticationFlowContext?) {

        if (isContextDisable(context)) {
            return
        }
        val enteredCode: String? = context!!.httpRequest.decodedFormParameters.getFirst(Constants.SMS_CODE)

        val authSession = context.authenticationSession
        val code: String? = authSession.getAuthNote(Constants.SMS_CODE)
        val ttl: Long? = authSession.getAuthNote(Constants.SMS_TTL)?.toLong()
        val smsCodeTTL: Long? = authSession.getAuthNote(Constants.SMS_CODE_TTL)?.toLong()
        val codeLength: Int? = authSession.getAuthNote(Constants.SMS_CODE_LENGTH)?.toInt()
        val isStubEnable: Boolean? = authSession.getAuthNote(Constants.SMS_STUB_SWITCH)?.toBoolean()
        val stubCode: String? = authSession.getAuthNote(Constants.SMS_STUB_CODE)

        // если хотя бы один параметр не получен - выходим с ошибкой
        if (isAuthNotesEmpty(context, enteredCode, ttl, code, smsCodeTTL, codeLength, isStubEnable, stubCode)) {
            return
        }
        if (enteredCode!! == code) {
            if (ttl!! < System.currentTimeMillis()) {
                // expired
                challengeSmsForm(context, isStubEnable!!, stubCode!!,
                    codeLength!!, smsCodeTTL!!,"smsAuthCodeExpired")
            } else {
                // valid
                context.success()
            }
        } else {
            // invalid
            val execution = context.execution
            if (execution.isRequired) {
                context.failureChallenge(
                    AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setAttribute("realm", context.realm)
                        .setError("smsAuthCodeInvalid").createForm(TPL_CODE)
                )
            } else if (execution.isConditional || execution.isAlternative) {
                context.attempted()
            }
        }
    }


    /**
     * Выполняет проверку наличия всех требуемых параметров для продолжения работы
     * @param context контекст потока аутентификации
     * @param enteredCode введенный пользователем секретный код
     * @param ttl пороговое значение тайм-аута в миллисекундах
     * @param code значение ожидаемого секретного кода
     * @param smsCodeTTL заданное значение TTL в секундах
     * @param codeLength заданная длина секретного кода
     * @param isStubEnable заданный признак симуляции кода
     * @param stubCode заданное значение секретного кода симуляции
     * @return true если хотя бы один из параметров пустой
     */
    private fun isAuthNotesEmpty(
        context: AuthenticationFlowContext,
        enteredCode: String?,
        ttl: Long?,
        code: String?,
        smsCodeTTL: Long?,
        codeLength: Int?,
        isStubEnable: Boolean?,
        stubCode: String?,
    ): Boolean {

        logger.info(">>>> Received ttl = $ttl")
        logger.info(">>>> Received ttl value = $smsCodeTTL")
        logger.info(">>>> Received secret code = $code")
        logger.info(">>>> Received entered code = $enteredCode")
        logger.info(">>>> Received entered code length = $codeLength")
        logger.info(">>>> Received isStubEnable = $isStubEnable")
        logger.info(">>>> Received stub code = $stubCode")

        if (code == null || ttl == null || enteredCode == null
            || isStubEnable == null || stubCode == null || codeLength == null || smsCodeTTL == null) {

            logger.info("Invalid parameters :: ")
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR))
            return true
        }
        return false
    }


    /**
     * Проверяет состояние контекста потока аутентификации, и если он пустой, выдаем ошибку
     *
     * @param context контекст потока аутентификации
     * @return true если поток пустой
     */
    private fun isContextDisable(context: AuthenticationFlowContext?): Boolean {

        if (context == null) {
            context?.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR))
            logger.warn("!!!! >>>> Authentication flow unavailable >>>> !!!!")
            return true
        }
        return false
    }


    /**
     * Формирует секретный код для отправки по СМС, создает атрибуты для передачи в UI форму ввода СМС и
     * затем формирует и вызывает UI форму ввода СМС методом context.challenge()
     *
     * @param context контекст потока аутентификации
     * @param isStubEnable признак работы в режиме симуляции
     * @param stubCode значение секретного кода в режиме симуляции
     * @param codeLength количество знаков в секретном коде, необходимо для генерации
     * @param smsCodeTTL там-аут процесса ввода секретного кода СМС, после которого
     * старый код станет не действителен, будет сформирован новый для нового проверочного ввода
     */
    private fun challengeSmsForm(
        context: AuthenticationFlowContext,
        isStubEnable: Boolean,
        stubCode: String,
        codeLength: Int,
        smsCodeTTL: Long,
        error: String?
    ) {
        // формируем секретный код для отправки СМС
        val code = if (isStubEnable) {
            // используется режим симуляции, значение кода = заданному в конфигурации значению stub value
            stubCode
        } else {
            // генерируем безопасный секретный код, он должен быть отправлен пользователю по СМС далее
            SecretGenerator.getInstance().randomString(codeLength, SecretGenerator.DIGITS)
        }
        // чтобы мы могли посмотреть в логах код - отобразим его для режима разработки
        logger.info(">>>> Created SMS secret code = $code")

        // вычисляем значение TTL для проверки тайм-аута
        val ttl = (System.currentTimeMillis() + (smsCodeTTL * Timer.ONE_SECOND))
        // вносим данные в карту параметров AuthNote для передачи в UI форму
        val authSession = context.authenticationSession
        authSession.setAuthNote(Constants.SMS_CODE, code)
        authSession.setAuthNote(Constants.SMS_TTL, ttl.toString())
        authSession.setAuthNote(Constants.SMS_STUB_SWITCH, isStubEnable.toString())
        authSession.setAuthNote(Constants.SMS_CODE_LENGTH, codeLength.toString())
        authSession.setAuthNote(Constants.SMS_CODE_TTL, smsCodeTTL.toString())
        authSession.setAuthNote(Constants.SMS_STUB_CODE, stubCode)
        /*
        TODO - здесь должен быть вызов метода отправки SMS
        */
        // и вызываем UI форму ввода кода СМС
        val initProvider = context.form().setAttribute("realm", context.realm)
        val finalProvider =
            if (error.isNullOrEmpty()) initProvider else initProvider.setError(error)
        val response = finalProvider.createForm(TPL_CODE)
        context.challenge(response)
    }


    override fun requiresUser(): Boolean {
        return true
    }

    /**
     * Данный шаг актуален только если у пользователя задано номер телефона
     * @param session сессия keycloak
     * @param realm ресурс области сервисов
     * @param user ресурс пользователя
     * @return true если нужно выполнить шаг
     */
    override fun configuredFor(
        session: KeycloakSession?,
        realm: RealmModel?,
        user: UserModel?
    ): Boolean {
        return user?.getFirstAttribute("phone") != null
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