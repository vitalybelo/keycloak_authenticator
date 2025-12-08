package keycloak.spi.sms_code_otp

import org.jboss.logging.Logger
import jakarta.ws.rs.core.Response
import keycloak.spi.common.AuthenticationUtils
import keycloak.spi.constants.Constants
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
        private val authenticationUtils = AuthenticationUtils()
        private const val TPL_CODE = "login-sms.ftl"
        private const val ATTRIBUTE_PHONE = "phone"
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

        authenticationUtils.contextEnabledOrNull(context) ?: return

        logger.info(">>>> username = ${context!!.user.username}")
        val smsAuthConfig = SmsAuthConfig(context)

        try {
            challengeSmsForm(context, smsAuthConfig, null)
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

        authenticationUtils.contextEnabledOrNull(context) ?: return

        val enteredCode: String? = context!!.httpRequest.decodedFormParameters.getFirst(Constants.SMS_CODE)
        val smsAuth = receiveAuthNotesOrNull(context, enteredCode) ?: return

        // если хотя бы один параметр не получен - выходим с ошибкой
        if (enteredCode!! == smsAuth.code) {
            if (smsAuth.ttl!! < System.currentTimeMillis()) {
                // expired
                challengeSmsForm(context, smsAuth, "smsAuthCodeExpired")
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
     *
     * @param context контекст потока аутентификации
     * @param enteredCode введенный пользователем секретный код
     * @return дата класс параметров аутентификатора
     */
    private fun receiveAuthNotesOrNull(

        context: AuthenticationFlowContext,
        enteredCode: String?
    ): SmsAuthConfig? {

        val smsAuthConfig = SmsAuthConfig()
        val authSession = context.authenticationSession

        smsAuthConfig.code = authSession.getAuthNote(Constants.SMS_CODE)
        smsAuthConfig.ttl = authSession.getAuthNote(Constants.SMS_TTL)?.toLong()
        smsAuthConfig.smsCodeTTL = authSession.getAuthNote(Constants.SMS_CODE_TTL)?.toLong()
        smsAuthConfig.codeLength = authSession.getAuthNote(Constants.SMS_CODE_LENGTH)?.toInt()
        smsAuthConfig.isStubEnable = authSession.getAuthNote(Constants.SMS_STUB_SWITCH)?.toBoolean()
        smsAuthConfig.stubCode = authSession.getAuthNote(Constants.SMS_STUB_CODE)

        logger.info(">>>> Received ttl = ${smsAuthConfig.ttl}")
        logger.info(">>>> Received ttl value = ${smsAuthConfig.smsCodeTTL}")
        logger.info(">>>> Received secret code = ${smsAuthConfig.code}")
        logger.info(">>>> Received entered code = $enteredCode")
        logger.info(">>>> Received entered code length = ${smsAuthConfig.codeLength}")
        logger.info(">>>> Received isStubEnable = ${smsAuthConfig.isStubEnable}")
        logger.info(">>>> Received stub code = ${smsAuthConfig.stubCode}")

        if (smsAuthConfig.isNullOrEmpty() || enteredCode == null) {
            logger.info("Invalid parameters :: ")
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR))
            return null
        }
        return smsAuthConfig
    }


    /**
     * Формирует секретный код для отправки по СМС, создает атрибуты для передачи в UI форму ввода СМС и
     * затем формирует и вызывает UI форму ввода СМС методом context.challenge()
     *
     * @param context контекст потока аутентификации
     * @param smsAuthConfig параметры настройки для работы аутентификатора 2FA SMS
     * @param error сообщение об ошибке (нужно для создания повторных UI форм ввода кода)
     * старый код станет не действителен, будет сформирован новый для нового проверочного ввода
     */
    private fun challengeSmsForm(

        context: AuthenticationFlowContext,
        smsAuthConfig: SmsAuthConfig,
        error: String?
    ) {
        // формируем секретный код для отправки СМС
        val secretCode = if (smsAuthConfig.isStubEnable == true) {
            // используется режим симуляции, значение кода = заданному в конфигурации значению stub value
            smsAuthConfig.stubCode
        } else {
            // генерируем безопасный секретный код, он должен быть отправлен пользователю по СМС далее
            SecretGenerator.getInstance().randomString(smsAuthConfig.codeLength!!, SecretGenerator.DIGITS)
        }
        // чтобы мы могли посмотреть в логах код - отобразим его для режима разработки
        logger.info(">>>> Created SMS secret code = $secretCode")

        // вычисляем значение TTL для проверки тайм-аута
        val ttl = (System.currentTimeMillis() + (smsAuthConfig.smsCodeTTL!! * Timer.ONE_SECOND))
        // вносим данные в карту параметров AuthNote для передачи в UI форму
        val authSession = context.authenticationSession
        authSession.setAuthNote(Constants.SMS_CODE, secretCode)
        authSession.setAuthNote(Constants.SMS_TTL, ttl.toString())
        authSession.setAuthNote(Constants.SMS_STUB_SWITCH, smsAuthConfig.isStubEnable.toString())
        authSession.setAuthNote(Constants.SMS_CODE_LENGTH, smsAuthConfig.codeLength.toString())
        authSession.setAuthNote(Constants.SMS_CODE_TTL, smsAuthConfig.smsCodeTTL.toString())
        authSession.setAuthNote(Constants.SMS_STUB_CODE, smsAuthConfig.stubCode)
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
        return !user?.getFirstAttribute(ATTRIBUTE_PHONE).isNullOrEmpty()
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