package keycloak.spi.telegram.resource

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.GET
import jakarta.ws.rs.POST
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import keycloak.spi.telegram.model.TgUpdate
import org.jboss.logging.Logger
import org.keycloak.connections.infinispan.InfinispanConnectionProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.services.resource.RealmResourceProvider
import java.util.concurrent.TimeUnit

class TelegramResourceProvider(private val session: KeycloakSession) : RealmResourceProvider {

    companion object {
        private val logger = Logger.getLogger(TelegramResourceProvider::class.java)
        private const val CACHE_CHAT_ID_TTL = 5L // столько минут будет лежать полученный chat id в infinispan
    }

    private val mapper: ObjectMapper = jacksonObjectMapper()

    override fun getResource(): Any = this


    @GET
    @Path("status/{token}")
    @Produces(MediaType.APPLICATION_JSON)
    fun checkStatus(@PathParam("token") token: String): Response {
        val cache = session
            .getProvider(InfinispanConnectionProvider::class.java)
            .getCache<String, String>(InfinispanConnectionProvider.WORK_CACHE_NAME)

        val chatId = cache?.get(token)

        val jsonResponse = if (chatId != null) {
            "{\"status\":\"linked\"}"
        } else {
            "{\"status\":\"waiting\"}"
        }

        return Response.ok(jsonResponse).build()
    }


    /**
     * Webhook-эндпоинт для приема push-уведомлений от серверов Telegram.
     */
    @POST
    @Path("webhook")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    fun handleTelegramWebhook(payload: String): Response {
        try {
            val update = mapper.readValue(payload, TgUpdate::class.java)
            val text = update.message?.text
            val chatId = update.message?.chat?.id

            if (chatId != null && !text.isNullOrBlank() && text.startsWith("/start ")) {
                val token = text.removePrefix("/start ").trim()
                logger.debug(">>>> Webhook received Telegram chat id: $chatId for token = $token")

                val cache = session
                    .getProvider(InfinispanConnectionProvider::class.java)
                    .getCache<String, String>(InfinispanConnectionProvider.WORK_CACHE_NAME)

                cache?.put(token, chatId.toString(), CACHE_CHAT_ID_TTL, TimeUnit.MINUTES)
            }
        } catch (ex: Exception) {
            logger.error(">>>> Error processing Telegram webhook: ${ex.message}")
            logger.debug(ex.message, ex)
        }

        // Возвращаем явный JSON и тип, чтобы фильтры Keycloak не падали
        return Response.ok("{\"status\":\"ok\"}", MediaType.APPLICATION_JSON).build()
    }
    
    override fun close() {}
}