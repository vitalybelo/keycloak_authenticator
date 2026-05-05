package keycloak.spi.telegram.auth

import keycloak.spi.constants.Constants
import keycloak.spi.telegram.model.TelegramAuthenticationConfig
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.Authenticator
import org.keycloak.common.util.SecretGenerator
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import java.net.InetSocketAddress
import java.net.ProxySelector
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

/**
 * Провайдер аутентификатора ввода временного кода 2FA отправленного через telegram
 * @author Belotserkovskii Vitalii (c) 05.03.2026
 */
class TelegramAuthenticator : Authenticator {

    companion object {
        private val logger = Logger.getLogger(TelegramAuthenticator::class.java)
        private const val ONE_SECOND = 1000L
    }
    private val botSecretToken = Constants.TELEGRAM_BOT_TOKEN
    private val client = HttpClient.newBuilder()
        .proxy(ProxySelector.of(InetSocketAddress("127.0.0.1", 12334)))
        .build()
    // TODO - убрать прокси для промышленного применения = HttpClient.newHttpClient()

    /**
     * Вначале генерится шестизначный секретный код для отправки в телеграм. Код сохраняется в атрибутах
     * сессии аутентификации для проверки в методе action. Затем вызывается метод отправки сообщения пользователю
     * по chat_id (заранее извлеченному из атрибутов). Затем создаем форму ввода временного кода и завершаем
     * работу, управление передается в метод action() и продолжается там до успешного ввода.
     * @param context контекст аутентификации
     */
    override fun authenticate(context: AuthenticationFlowContext) {

        val config = TelegramAuthenticationConfig.init(context)

        if (!config.isSwitchedOn) { // выходим успешно, если вход 2FA через telegram отключен
            logger.debug(">>>> Telegram Authenticator is disabled")
            context.success()
            return
        }

        val chatId = context.user.getFirstAttribute(Constants.TELEGRAM_CHAT_ID_ATTRIBUTE)
        logger.debug(">>>> Telegram Authentication started with chatId = $chatId")

        if (chatId.isNullOrBlank()) {
            logger.debug(">>>> Telegram Authentication finished and activate telegram bind action")
            context.user.addRequiredAction(Constants.TELEGRAM_BIND_ACTION_ID)
            context.success()
            return
        }

        var otpCode = context.authenticationSession.getAuthNote(Constants.TELEGRAM_AUTH_NOTE_CODE)
        if (otpCode.isNullOrEmpty()) {
            otpCode = SecretGenerator.getInstance().randomString(config.codeLength, SecretGenerator.DIGITS)

            val currentMillisString = System.currentTimeMillis().toString()
            context.authenticationSession.setAuthNote(Constants.TELEGRAM_AUTH_NOTE_CODE, otpCode)
            context.authenticationSession.setAuthNote(Constants.TELEGRAM_AUTH_NOTE_TIME, currentMillisString)
            sendTelegramMessage(chatId, "Ваш код для входа: *${otpCode}*") // отправляем сообщение в telegram
        }

        val form = context.form().createForm("telegram-otp.ftl") // показываем форму для ввода кода
        context.challenge(form)
    }


    /**
     * Метод получает введенное пользователем значение из формы ввода кода подтверждение = otp.
     * Сравнивает его, и в случае верного ввода, метод завершается успешно для контекста аутентификации.
     * Иначе, выдается сообщение о неверно введенном коде, и бесконечно ждем верного ввода
     * @param context контекст аутентификации
     */
    override fun action(context: AuthenticationFlowContext) {

        val formData = context.httpRequest.decodedFormParameters
        val enteredCode = formData.getFirst("otp")
        val expectedCode = context.authenticationSession.getAuthNote(Constants.TELEGRAM_AUTH_NOTE_CODE)
        val createTimeString = context.authenticationSession.getAuthNote(Constants.TELEGRAM_AUTH_NOTE_TIME)

        // проверяем ttl временного кода
        val createTime = createTimeString.toLongOrNull() ?: 0L
        val config = TelegramAuthenticationConfig.init(context)
        val isExpired = (System.currentTimeMillis() - createTime) > (config.ttlSeconds * ONE_SECOND)

        if (expectedCode == null || isExpired) {
            // обновляем код, отправляем в бот, создаем форму и запускаем челендж
            refreshCodeAndChallengeForm(context, config.codeLength)
            return
        }

        if (enteredCode != null && enteredCode == expectedCode) {
            // код верный
            removeSessionAuthNotes(context)
            context.success()
        } else {
            // код неверный
            context.event.error("invalid_telegram_otp")
            val form = context.form()
                .setError("Неверный код. Попробуйте снова.")
                .createForm("telegram-otp.ftl")

            context.failureChallenge(
                org.keycloak.authentication.AuthenticationFlowError.INVALID_CREDENTIALS, form
            )
        }
    }


    /**
     * Очищаем заметки в сессии, который мы делали для передачи данных из authenticate() в action()
     * @param context контекст аутентификации
     */
    private fun removeSessionAuthNotes(context: AuthenticationFlowContext) {

        context.authenticationSession.removeAuthNote(Constants.TELEGRAM_AUTH_NOTE_CODE)
        context.authenticationSession.removeAuthNote(Constants.TELEGRAM_AUTH_NOTE_TIME)
    }


    /**
     * Создает новый временный код и отправляет его в telegram, заранее обновляет значение кода и время его
     * создания в AuthNotes сессии, чтобы метод action() смог прочитать новые значения для проверки. Далее
     * создает новую форму и запускает challenge ввода нового временного кода
     * @param context контекст потока аутентификации
     * @param codeLength количество цифр во временном коде
     */
    private fun refreshCodeAndChallengeForm(
        context: AuthenticationFlowContext,
        codeLength: Int,
    ) {
        // создаем новый код и обновляем в сессии его значение и время создания перед challenge
        val currentMillisString = System.currentTimeMillis().toString()
        val newOtpCode = SecretGenerator.getInstance().randomString(codeLength, SecretGenerator.DIGITS)
        context.authenticationSession.setAuthNote(Constants.TELEGRAM_AUTH_NOTE_CODE, newOtpCode)
        context.authenticationSession.setAuthNote(Constants.TELEGRAM_AUTH_NOTE_TIME, currentMillisString)

        // отправляем новый код пользователю
        val chatId = context.user.getFirstAttribute(Constants.TELEGRAM_CHAT_ID_ATTRIBUTE)
        sendTelegramMessage(chatId, "Время предыдущего кода истекло. Ваш новый код для входа: *${newOtpCode}*")

        // логируем событие истечения кода (для аудита Keycloak)
        context.event.error("expired_telegram_otp")

        // отрисовываем форму заново с понятным сообщением
        val form = context.form()
            .setError("Время действия кода истекло. Мы отправили вам новый код в Telegram.")
            .createForm("telegram-otp.ftl")

        context.challenge(form)
    }


    /**
     * Выполняет отправку сообщения в телеграм, в бот аутентификации, пользователю по chat_id
     * В сообщение указан временный код, необходимый для проверки входа по второму фактору
     * @param chatId идентификатор пользователя в телеграм
     * @param text текст сообщения, включающий секретный код
     */
    private fun sendTelegramMessage(
        chatId: String,
        text: String
    ) {
        try {
            val url = "https://api.telegram.org/bot$botSecretToken/sendMessage" // вызов API Telegram
            val body = """{"chat_id": "$chatId", "text": "$text", "parse_mode": "Markdown"}"""
            logger.debug(">>>> Sending telegram message: $body")

            val request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build()

            client.send(request, HttpResponse.BodyHandlers.ofString())

        } catch (ex: Exception) {
            logger.error(">>>> Error while sending telegram message, message = ${ex.message}, cause = ${ex.cause}")
            logger.debug(ex)
        }
    }

    /**
     * Описание магии, которая может пригодиться при использовании configuredFor() и setRequiredActions().
     * Итак, метод configuredFor() проверяет, есть ли у пользователя нужный атрибут для входа через telegram.
     * Если атрибут есть, все нормально, мы попадаем в метод authenticate() и выполняем проверку 2FA входа.
     * Но если атрибута нет, сработает магия keycloak, он автоматически вызовет метод setRequiredActions().
     * Который установит обязательное выполнение требуемой акции TelegramBindRequiredActionFactory, по
     * привязке пользователя к telegram, но после этого authenticate() уже не будет вызван
     * единственное условие - наш аутентификатор должен иметь режим REQUIRED
     * тогда метод configuredFor() выглядел бы так
     *
     * ```override fun configuredFor(session: KeycloakSession, realm: RealmModel, user: UserModel): Boolean {
     *          val chatId: String? = user.getFirstAttribute(Constants.TELEGRAM_CHAT_ID_ATTRIBUTE)
     *          logger.debug(">>>> Authenticator configured for ${user.username} :: chatId = $chatId")
     *          return !chatId.isNullOrBlank()
     *    }
     * ```
     * Но если аутентификатор стоит в режиме ALTERNATIVE - authenticate() не будет вызван вообще никогда.
     * Значит мы не сможем здесь использовать магию, поэтому просто вернем true и разберемся дальше.
     */
    override fun configuredFor(session: KeycloakSession, realm: RealmModel, user: UserModel): Boolean = true

    /**
     * Если configuredFor вернул бы false, а аутентификатор обязателен - сработает условие из-под капота.
     * Именно, keycloak сам вызовет этот метод, чтобы повесить нужный нам экшен - магия механизма Keycloak
     */
    override fun setRequiredActions(session: KeycloakSession, realm: RealmModel, user: UserModel) {
        logger.debug(">>>> Set required actions to bind telegram user")
        user.addRequiredAction(Constants.TELEGRAM_BIND_ACTION_ID)
    }

    override fun requiresUser(): Boolean = true
    override fun close() {}
}