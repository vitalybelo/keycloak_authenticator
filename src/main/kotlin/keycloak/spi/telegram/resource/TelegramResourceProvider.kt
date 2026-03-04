package keycloak.spi.telegram.resource

import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import org.keycloak.connections.infinispan.InfinispanConnectionProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.services.resource.RealmResourceProvider

class TelegramResourceProvider(private val session: KeycloakSession) : RealmResourceProvider {

    override fun getResource(): Any = this

    @GET
    @Path("status/{token}")
    @Produces(MediaType.APPLICATION_JSON)
    fun checkStatus(@PathParam("token") token: String): Response {

        /*
        проверяем в infinispan - пришел ли ответ о привязке
        Polling выполняется scheduleWithFixedDelay в TelegramBindRequiredActionFactory
        он каждую секунду отправляет запросы в telegram за updates, и делает запись в infinispan
        если получает результат привязки пользователя к боту второго фактора Unicredit CA 2FA
        а здесь мы просто проверяем, существует ли запись сделанная в scheduleWithFixedDelay()
        то есть, выполнена ли привязка пользователя по uuid сформированному для него
        */
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

    override fun close() {}
}