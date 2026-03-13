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

        val chatId = context.user?.getFirstAttribute(Constants.TELEGRAM_CHAT_ID_ATTRIBUTE)
        if (chatId == null) {
            context.authenticationSession.addRequiredAction(Constants.TELEGRAM_BIND_ACTION_ID)
            logger.debug(">>>> evaluateTriggers() :: user should bind to telegram")
        } else {
            logger.debug(">>>> evaluateTriggers() :: user chatId: [$chatId] provided")
        }
    }


    /**
     * Выполняет генерацию uuid для первоначального запроса в telegram по привязке пользователя.
     * Сохраняет в атрибутах сессии этот uuid для последующего использования и вызывает форму привязки
     * @param context контекст потока аутентификации
     */
    override fun requiredActionChallenge(context: RequiredActionContext) {

        // генерируем uuid для привязки, его добавим в /start ***
        val token = UUID.randomUUID().toString()
        context.authenticationSession.setAuthNote(Constants.TELEGRAM_TOKEN_KEY, token)
        logger.debug(">>>> Start procedure binding to telegram with token = $token")

        // создаем форму и передаем туда токен (чтобы FTL сгенерировал QR и ссылку)
        val form = context.form()
            .setAttribute("tgToken", token)
            .createForm("telegram-bind.ftl")

        context.challenge(form)
    }


    /**
     * Здесь мы проверяем, закончена ли требуемая акция по привязке аккаунта к telegram.
     * Если форма отдает нам финальный сабмит, это означает что пользователь выполнил команду /start,
     * и telegram вернул нам в webhook идентификатор пользователя из нашего боте аутентификации, который
     * в методе получения webhook помещается в infinispan. Здесь мы вычитываем из кэша infinispan этот
     * идентификатор и записываем его пользователю в атрибуты. Завершаемся успехом. Если финальный
     * сабмит не получен, перерисовываем форму и продолжаем ждать пока не закончится привязка
     * @param context контекст потока аутентификации
     */
    override fun processAction(context: RequiredActionContext) {

        val formData = context.httpRequest.decodedFormParameters
        val token = context.authenticationSession.getAuthNote(Constants.TELEGRAM_TOKEN_KEY)

        val cache = session
            .getProvider(InfinispanConnectionProvider::class.java)
            .getCache<String, String>(InfinispanConnectionProvider.WORK_CACHE_NAME)

        // обработка финального сабмита от формы
        if (formData.containsKey("final_submit")) {
            // достаем chatId напрямую из кэша (REST эндпоинт его не удалял, он просто проверял)
            val chatId = cache?.get(token)

            if (chatId != null) {
                // сохраняем Telegram ID в БД пользователя
                context.user.setSingleAttribute(Constants.TELEGRAM_CHAT_ID_ATTRIBUTE, chatId)

                // подчищаем за собой
                cache.remove(token)
                context.authenticationSession.removeAuthNote(Constants.TELEGRAM_TOKEN_KEY)

                // успех! Пропускаем пользователя дальше
                context.success()
            } else {
                // если почему-то submit пришел, а в кэше пусто - возвращаем форму с ошибкой
                val form = context.form()
                    .setAttribute("tgToken", token)
                    .setError("Ошибка привязки. Попробуйте еще раз.")
                    .createForm("telegram-bind.ftl")
                context.challenge(form)
            }
            return
        }

        // если форма отправлена некорректно, рисуем ее заново
        val form = context.form()
            .setAttribute("tgToken", token)
            .createForm("telegram-bind.ftl")

        context.challenge(form)
    }

    override fun close() {
        // освобождение ресурсов провайдера (если есть)
    }
}