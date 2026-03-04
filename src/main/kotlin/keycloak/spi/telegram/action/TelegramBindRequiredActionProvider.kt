package keycloak.spi.telegram.action

import keycloak.spi.constants.Constants
import org.jboss.logging.Logger
import org.keycloak.authentication.RequiredActionContext
import org.keycloak.authentication.RequiredActionProvider
import org.keycloak.connections.infinispan.InfinispanConnectionProvider
import org.keycloak.models.KeycloakSession
import java.util.UUID

/**
 *
 */
class TelegramBindRequiredActionProvider(

    private val session: KeycloakSession
) : RequiredActionProvider {

    companion object {
        private val logger = Logger.getLogger(TelegramBindRequiredActionProvider::class.java)
    }

    /**
     * Этот метод проверяет наличие у пользователя атрибута для хранения chat id telegram
     * Если данный атрибут не найдет, автоматически пользователю назначается required action
     */
    override fun evaluateTriggers(context: RequiredActionContext) {

        val chatId = context.user.getFirstAttribute(Constants.TELEGRAM_CHAT_ID_ATTRIBUTE)
        if (chatId == null) {
            context.authenticationSession.addRequiredAction(Constants.TELEGRAM_BIND_ACTION_ID)
        }
    }

    /**
     * Выполняет генерацию uuid для первоначального запроса в telegram по привязке пользователя.
     * Сохраняет в атрибутах сессии этот uuid для последующего использования и вызывает форму привязки
     * @param context контекст аутентификации
     */
    override fun requiredActionChallenge(context: RequiredActionContext) {

        // генерируем uuid для привязки, его добавим в /start ***
        val token = UUID.randomUUID().toString()
        context.authenticationSession.setAuthNote("tg_token", token)
        logger.debug(">>>> Start procedure binding to telegram with token = $token")

        // создаем форму и передаем туда токен (чтобы FTL сгенерировал QR и ссылку)
        val form = context.form()
            .setAttribute("tgToken", token)
            .createForm("telegram-bind.ftl")

        context.challenge(form)
    }

    /**
     *
     */
    override fun processAction(context: RequiredActionContext) {
        val formData = context.httpRequest.decodedFormParameters
        val token = context.authenticationSession.getAuthNote("tg_token")

        val cache = session.getProvider(InfinispanConnectionProvider::class.java)
            .getCache<String, String>(InfinispanConnectionProvider.WORK_CACHE_NAME)

        // Обработка финального сабмита от формы
        if (formData.containsKey("final_submit")) {
            // Достаем chatId напрямую из кэша (REST эндпоинт его не удалял, он просто проверял)
            val chatId = cache?.get(token)

            if (chatId != null) {
                // Сохраняем Telegram ID в БД пользователя
                context.user.setSingleAttribute(Constants.TELEGRAM_CHAT_ID_ATTRIBUTE, chatId)

                // Подчищаем за собой
                cache.remove(token)
                context.authenticationSession.removeAuthNote("tg_token")

                // Успех! Пропускаем пользователя дальше
                context.success()
            } else {
                // Если почему-то submit пришел, а в кэше пусто - возвращаем форму с ошибкой
                val form = context.form()
                    .setAttribute("tgToken", token)
                    .setError("Ошибка привязки. Попробуйте еще раз.")
                    .createForm("telegram-bind.ftl")
                context.challenge(form)
            }
            return
        }

        // Если форма отправлена некорректно, рисуем ее заново
        val form = context.form().setAttribute("tgToken", token).createForm("telegram-bind.ftl")
        context.challenge(form)
    }

    override fun close() {
        // Освобождение ресурсов провайдера (если есть)
    }
}