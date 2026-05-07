package keycloak.spi.custom_resources.migration

import jakarta.ws.rs.POST
import jakarta.ws.rs.Path
import jakarta.ws.rs.Produces
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import org.jboss.logging.Logger
import org.keycloak.events.admin.ResourceType
import org.keycloak.events.admin.OperationType
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.services.resources.admin.AdminEventBuilder
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator

/**
 * Ресурс управления атрибутом Branch миграции пользователя.
 * @author Belotserkovskii Vitalii (c) 07.05.2026
 */
class BranchMigrationResource(

    private val session: KeycloakSession,
    private val realm: RealmModel,
    private val auth: AdminPermissionEvaluator,
    private val adminEvent: AdminEventBuilder
) {

    companion object {
        private val logger = Logger.getLogger(BranchMigrationResource::class.java.name)
        const val INVALID_PARAMETERS = "invalid request parameters"
        const val USER_NOT_FOUND = "user not found"
        const val ERROR = "error"
    }

    /**
     * Выполняет поиск пользователя по заданному параметрами атрибуту в Keycloak.
     * В случае успешного поиска, меняет заданные атрибут пользователя на заданное значение
     * @param searchKey ключ атрибута поиска пользователя
     * @param searchValue значение атрибута поиска пользователя
     * @param modifyKey ключ изменяемого атрибута пользователя
     * @param modifyValue значение изменяемого атрибута пользователя
     * @return статус выполнения, сообщение выполнения
     */
    @POST
    @Path("users/migration")
    @Produces(MediaType.APPLICATION_JSON)
    fun updateMigrationAttribute(
        @QueryParam("searchKey") searchKey: String?,
        @QueryParam("searchValue") searchValue: String?,
        @QueryParam("modifyKey") modifyKey: String?,
        @QueryParam("modifyValue") modifyValue: String?
    ): Response {

        auth.users().requireManage()

        if (searchKey.isNullOrBlank() || searchValue.isNullOrBlank()
            || modifyKey.isNullOrBlank() || modifyValue.isNullOrBlank()) {
            logger.debug(">>>> $INVALID_PARAMETERS >>>>")
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(mapOf(ERROR to INVALID_PARAMETERS)).build()
        }

        return try {
            val userModel = session.users()
                .searchForUserByUserAttributeStream(realm, searchKey, searchValue)
                .findFirst().orElse(null)

            if (userModel == null) {
                logger.warn(">>>> $USER_NOT_FOUND >>>>")
                return Response.status(Response.Status.NOT_FOUND).
                    entity(mapOf(ERROR to USER_NOT_FOUND)).build()
            }

            userModel.setSingleAttribute(modifyKey, modifyValue)

            adminEvent.operation(OperationType.UPDATE)
                .resource(ResourceType.USER)
                .resourcePath("users", userModel.id)
                .representation("{\"action\": \"custom_migration\", \"$modifyKey\": \"$modifyValue\"}")
                .success()

            Response.ok(mapOf(
                searchKey to searchValue,
                modifyKey to modifyValue,
                "success" to "attribute modified effectively"
            )).build()

        } catch (ex: Exception) {
            logger.error(">>>> Modify user attribute failed :: message = ${ex.message}, cause = ${ex.cause}")
            Response.status(Response.Status.INTERNAL_SERVER_ERROR).build()
        }
    }



}