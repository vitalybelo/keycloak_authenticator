package keycloak.spi.trusted_device.resource

import jakarta.ws.rs.*
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import keycloak.spi.trusted_device.credentials.TrustedDeviceCredentialModel
import keycloak.spi.trusted_device.toTrustedDeviceModel
import org.jboss.logging.Logger
import org.keycloak.models.KeycloakSession
import org.keycloak.models.UserModel
import org.keycloak.services.managers.AppAuthManager


class TrustedDeviceResource(private val session: KeycloakSession) {

    private val logger = Logger.getLogger(TrustedDeviceResource::class.java)

    /**
     * Валидирует Bearer-токен (Access Token) из заголовка Authorization.
     * Возвращает модель пользователя, если токен валиден.
     */
    private fun authenticate(): UserModel {

        val authResult = AppAuthManager.BearerTokenAuthenticator(session).authenticate()
        if (authResult == null || authResult.user == null) {
            logger.warn(">>>> Unauthorized API access attempt")
            throw NotAuthorizedException("Bearer user token required")
        }
        return authResult.user
    }

    /**
     * Получить список всех доверенных устройств текущего пользователя.
     * GET /realms/{realm}/trusted-devices
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    fun getDevices(): Response {

        val user = authenticate()
        val devices = user.credentialManager()
            .getStoredCredentialsByTypeStream(TrustedDeviceCredentialModel.TYPE)
            .map { credential ->
                val trustedDevice = credential.toTrustedDeviceModel()
                TrustedDeviceDto(
                    id = credential.id,
                    deviceName = trustedDevice.userLabel ?: "Unknown Device",
                    createdAt = trustedDevice.createdDate ?: 0L
                )
            }.toList()

        if (devices.isNullOrEmpty()) {
            return Response
                .status(Response.Status.NOT_FOUND)
                .entity(mapOf("message" to "trusted devices not found for user = ${user.username}")).build()
        }
        return Response.ok(devices).build()
    }


    /**
     * Кнопка "Удалить устройство" - удаляет конкретное устройство по его идентификатору.
     * DELETE /realms/{realm}/trusted-devices/{id}
     * @param credentialId идентификатор кредов
     */
    @DELETE
    @Path("/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    fun deleteDevice(
        @PathParam("id") credentialId: String
    ): Response {

        val user = authenticate()
        val isRemoved = user.credentialManager().removeStoredCredentialById(credentialId)

        return if (isRemoved) {
            logger.info(">>>> User ${user.username} successfully deleted trusted device: $credentialId")
            Response.ok(mapOf("success" to "device [$credentialId] deleted")).build()
        } else {
            logger.info(">>>> User ${user.username} has not trusted device: $credentialId")
            Response
                .status(Response.Status.NOT_FOUND)
                .entity(mapOf("message" to "device [${credentialId}] not found")).build()
        }
    }

    /**
     * Кнопка "Выйти со всех устройств" — удаляет все доверенные устройства пользователя.
     * DELETE /realms/{realm}/trusted-devices/all
     */
    @DELETE
    @Path("/all")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    fun deleteAllDevices(): Response {

        val user = authenticate()
        val credentials = user.credentialManager()
            .getStoredCredentialsByTypeStream(TrustedDeviceCredentialModel.TYPE).toList()

        if (credentials.isNullOrEmpty()) {
            return Response
                .status(Response.Status.NOT_FOUND)
                .entity(mapOf("message" to "trusted devices not found")).build()
        }

        var deletedCount = 0
        credentials.forEach { credential ->
            if (user.credentialManager().removeStoredCredentialById(credential.id)) {
                deletedCount++
            }
        }
        logger.info(">>>> User ${user.username} deleted all trusted devices (count: $deletedCount)")
        return Response.ok().entity(mapOf("success" to "deleted $deletedCount credentials")).build()
    }


    /**
     * Разрешаем preflight-запросы (CORS), если ваше SPA (React/Vue/Angular)
     * будет дергать API с другого домена.
     */
    @OPTIONS
    @Path("{any:.*}")
    fun preflight(): Response {
        return Response.ok()
            .header("Access-Control-Allow-Origin", "*") // В проде лучше указать конкретный домен
            .header("Access-Control-Allow-Methods", "GET, DELETE, OPTIONS")
            .header("Access-Control-Allow-Headers", "Authorization, Content-Type")
            .build()
    }
}