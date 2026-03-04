package keycloak.spi.telegram.action

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import keycloak.spi.constants.Constants
import keycloak.spi.telegram.model.TgResponse
import org.jboss.logging.Logger
import org.keycloak.Config
import org.keycloak.authentication.RequiredActionFactory
import org.keycloak.authentication.RequiredActionProvider
import org.keycloak.connections.infinispan.InfinispanConnectionProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.models.utils.KeycloakModelUtils
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit


/**
 * Фабрика провайдера привязки двухфакторной аутентификации пользователя через telegram.
 * Отсюда вызывается провайдер для выполнения required action привязки, а также запускается шедуллер
 * при старте keycloak, который запрашивает у telegram специальный идентификатор (chat id) пользователя,
 * формирующийся на стороне telegram после нажатия кнопки /start внутри бота аутентификации telegram
 * (создан мной заранее). Для того, что запустить привязку пользователей к telegram, необходимо собрать
 * провайдер и поместить его в папку /providers сервера Keycloak, а затем в UI в разделе Authentication
 * во вкладе Required Action - активировать провайдер, и для применения всем выбрать его как Default**
 * @author Belotserkovskii Vitalii (c) 05.03.2026
 */
class TelegramBindRequiredActionFactory : RequiredActionFactory {

    companion object {
        private const val POLLING_IN_MINUTES = 1L   // частота выполнения пуллинга запросов в telegram
        private const val CONNECTION_TIMEOUT = 10L  // значение тайм-аута для запроса
        private const val CACHE_CHAT_ID_TTL = 5L    // время хранения полученного chat_id в infinispan
        private const val PROVIDER_ID = Constants.TELEGRAM_BIND_ACTION_ID
        private val logger = Logger.getLogger(TelegramBindRequiredActionFactory::class.simpleName)
    }

    private var executor: ScheduledExecutorService? = null
    private val botToken = Constants.TELEGRAM_BOT_TOKEN // его получаем после создания бота telegram
    private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(CONNECTION_TIMEOUT)).build()
    private val mapper: ObjectMapper = jacksonObjectMapper()

    @Volatile
    private var lastUpdateId: Long = 0 // ID последнего обработанного сообщения, чтобы сдвигать offset.

    override fun create(session: KeycloakSession): RequiredActionProvider {
        return TelegramBindRequiredActionProvider(session)
    }

    override fun init(config: Config.Scope) {
        logger.info(">>>> INITIALIZED >>>>")
    }

    /**
     * Здесь запускаем шедулер, который будет опрашивать telegram, для получения chat_id
     */
    override fun postInit(factory: KeycloakSessionFactory) {

        logger.info(">>>> Starting Telegram Bot Polling Thread... >>>>")
        executor = Executors.newSingleThreadScheduledExecutor()
        executor?.scheduleWithFixedDelay({
            pollTelegramUpdates(factory)
        }, 0, POLLING_IN_MINUTES, TimeUnit.SECONDS)
    }


    /**
     * Отправляет polling запрос в telegram для получения результата привязки = chat_id пользователя
     * Если запрос выполнен удачно, результат в виде первоначального токена и полученного chat_id
     * сохраняется в infinispan, чтобы провайдер смог его увидеть и выполнить окончательную привязку
     * пользователя - добавлением атрибута telegram_chat_id = полученный chat_id
     */
    private fun pollTelegramUpdates(factory: KeycloakSessionFactory) {
        try {
            /*
            параметр timeout=10 включает Long Polling на стороне серверов Telegram
            параметр offset говорит Telegram, начиная с какого сообщения мы хотим получить данные
            */
            val url = "https://api.telegram.org/bot$botToken/getUpdates?timeout=10&offset=$lastUpdateId"

            // делаем запрос, чтобы получить список updates от telegram
            val handler = HttpResponse.BodyHandlers.ofString()
            val request = HttpRequest.newBuilder().uri(URI.create(url)).GET().build()
            val response = client.send(request, handler)

            if (response.statusCode() == 200) {

                val tgResponse = mapper.readValue(response.body(), TgResponse::class.java)
                if (tgResponse.ok && !tgResponse.result.isNullOrEmpty()) {

                    // обрабатываем все полученные апдейты в рамках одной транзакции Keycloak
                    KeycloakModelUtils.runJobInTransaction(factory) { session ->

                        val cache = session
                            .getProvider(InfinispanConnectionProvider::class.java)
                            .getCache<String, String>(InfinispanConnectionProvider.WORK_CACHE_NAME)

                        for (update in tgResponse.result) {

                            val text = update.message?.text
                            val chatId = update.message?.chat?.id

                            // проверяем, что это именно команда /start
                            if (chatId != null
                                && !text.isNullOrBlank()
                                && text.startsWith("/start ")) {

                                // извлекаем токен сформированный нами для привязки в провайдере
                                val token = text.removePrefix("/start ").trim()
                                logger.debug("Received Telegram users's chat id: $chatId for request token = $token")

                                // кладем полученный уникальный идентификатор пользователя в telegram внутрь
                                // infinispan Keycloak: key = token сформированный для пользователя в начале
                                // процедуры привязки , value = chatId (уникальный id пользователя telegram)
                                // также задаем TTL хранения этой записи в минутах (дефолтное значение = 5мин)
                                cache.put(token, chatId.toString(), CACHE_CHAT_ID_TTL, TimeUnit.MINUTES)
                            }

                            // обновляем offset (обязательно + 1 от последнего полученного ID)
                            if (update.updateId >= lastUpdateId) {
                                lastUpdateId = update.updateId + 1
                            }
                        }
                    }
                }
            } else {
                logger.warn("Telegram API returned status: ${response.statusCode()}")
            }
        } catch (ex: Exception) {
            logger.error("Error during Telegram polling, message = $ex.message, cause = $ex.cause")
            logger.debug(ex.message, ex)
        }
    }

    override fun close() {
        executor?.shutdownNow()
    }
    override fun getId(): String = PROVIDER_ID
    override fun getDisplayText(): String = "Bind Telegram 2FA"
}