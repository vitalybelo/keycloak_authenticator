package keycloak.spi.custom_resources.admin

import jakarta.ws.rs.GET
import jakarta.ws.rs.PUT
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import keycloak.spi.custom_resources.admin.model.UserListDto
import keycloak.spi.jackson_mapper.toJsonString
import keycloak.spi.jackson_mapper.toPrettyJsonString
import org.eclipse.microprofile.openapi.annotations.media.Content
import org.eclipse.microprofile.openapi.annotations.media.Schema
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses
import org.keycloak.events.admin.OperationType
import org.keycloak.events.admin.ResourceType
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.services.resources.admin.AdminEventBuilder
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator
import java.util.stream.Collectors
import org.jboss.logging.Logger


class CustomAdminResource(

    private val session: KeycloakSession,
    private val realm: RealmModel,
    private val auth: AdminPermissionEvaluator,
    private val adminEventBuilder: AdminEventBuilder

) {

    companion object {
        private val logger = Logger.getLogger(CustomAdminResource::class.java)
    }


    /**
     * Выполняет чтение учетных записей рабочей области realm и возвращает все username
     * @return экземпляр класса UserListDto
     */
    @GET
    @Path("users/list")
    @Produces(MediaType.APPLICATION_JSON)
    fun getListOfUsers(): Response {

        val userPermissionEvaluator = auth.users()
        userPermissionEvaluator.requireQuery() // требуем роль для запроса

        val userList = session.users()
            ?.searchForUserStream(realm, mapOf(UserModel.SEARCH to "*"))
            ?.filter { userModel -> userModel.serviceAccountClientLink == null }
            ?.map { userModel -> userModel.username}
            ?.collect(Collectors.toList())
            ?: return Response.status(Response.Status.NOT_FOUND).entity("Users not found").build()


        val userCount = userList.size
        logger.info(">>>> Found $userCount users")
        val userListDto = UserListDto(userCount, userList)

        adminEventBuilder
            .realm(realm)
            .resource(ResourceType.USER)
            .representation(userList)
            .authRealm(realm)
            .authUser(auth.adminAuth().user)
            .operation(OperationType.ACTION)
            .detail("custom_filter", "exclude_service_accounts")
            .success()

        return Response.ok(userListDto).build()
    }


    /**
     * Выполняет обновление или добавление атрибутов пользователю заданному параметром userId
     * @param userId идентификатор пользователя
     * @param attributes карта атрибутов: ключ, значение
     * @return код выполнения и сообщение
     */
    @APIResponses(
        APIResponse(
            responseCode = "200",
            description = "Success updated attributes",
            content = [Content(schema = Schema(implementation = Response::class))]
        ),
        APIResponse(
            responseCode = "401",
            description = "Unauthorized",
            content = [Content(schema = Schema(implementation = Response::class))]
        ),
        APIResponse(
            responseCode = "403",
            description = "Forbidden to manage realm",
            content = [Content(schema = Schema(implementation = Response::class))]
        ),
        APIResponse(
            responseCode = "400",
            description = "Bad request. UserId or Attribute Map is invalid",
            content = [Content(schema = Schema(implementation = Response::class))]
        ),
        APIResponse(
            responseCode = "404",
            description = "User Not Found",
            content = [Content(schema = Schema(implementation = Response::class))]
        )
    )
    @PUT
    @Path("users/{userId}/attributes")
    @Produces(MediaType.APPLICATION_JSON)
    fun updateUserAttributes(

        @PathParam("userId") userId: String?,
        attributes: Map<String, String?>?
    ): Response {

        if (userId.isNullOrEmpty() || attributes.isNullOrEmpty())
            return Response.status(Response.Status.BAD_REQUEST).entity("Bad request").build()

        val userPermissionEvaluator = auth.users()
        userPermissionEvaluator.requireManage() // требуем роль для менеджмента

        val userModel = session.users()?.getUserById(realm, userId)
            ?: return Response.status(Response.Status.NOT_FOUND).entity("User not found").build()

        attributes.forEach { (key, value) ->
            if (value != null) {
                userModel.setSingleAttribute(key, value)
            }
        }

        adminEventBuilder
            .realm(realm)
            .resource(ResourceType.USER)
            .operation(OperationType.UPDATE)
            .representation(attributes)
            .detail("update-attributes", attributes.toString())
            .authUser(userModel)
            .success()

        return Response.ok("successfully").build()
    }


    /**
     * Выполняет проверку наличия временной блокировки в результате многократно введенных неверных
     * пар логин/пароль - brute force.
     * @param userId идентификатор пользователя
     */
    @APIResponses(
        APIResponse(
            responseCode = "200",
            description = "Login failures found",
            content = [Content(schema = Schema(implementation = Response::class))]
        ),
        APIResponse(
            responseCode = "401",
            description = "Unauthorized",
            content = [Content(schema = Schema(implementation = Response::class))]
        ),
        APIResponse(
            responseCode = "403",
            description = "Forbidden to query from realm",
            content = [Content(schema = Schema(implementation = Response::class))]
        ),
        APIResponse(
            responseCode = "400",
            description = "Bad request, userId is invalid",
            content = [Content(schema = Schema(implementation = Response::class))]
        ),
        APIResponse(
            responseCode = "404",
            description = "User not found",
            content = [Content(schema = Schema(implementation = Response::class))]
        ),
        APIResponse(
            responseCode = "410",
            description = "Gone successfully, but user login failures absent",
            content = [Content(schema = Schema(implementation = Response::class))]
        )
    )
    @GET
    @Path("users/{userId}/login-failures")
    @Produces(MediaType.APPLICATION_JSON)
    fun getLoginFailures(@PathParam("userId") userId: String?): Response {

        if (userId.isNullOrEmpty())
            return Response.status(Response.Status.BAD_REQUEST).entity("Bad request").build()
        logger.info(">>>> Received userId = $userId")

        val userPermissionEvaluator = auth.users()
        userPermissionEvaluator.requireQuery() // требуем роль для запроса

        val user = session.users().getUserById(realm, userId)
            ?: return Response.status(Response.Status.NOT_FOUND).entity("User not found").build()

        logger.info(">>>> Found user: ${user.username}")
        val failureProvider = session.loginFailures()
        val failureModel = failureProvider?.getUserLoginFailure(realm, user.id)
            ?: return Response.status(Response.Status.GONE).entity("No Login Failures for ${user.username}").build()

        logger.info(">>>> Login failures for user: ${user.username} found: ${failureModel.toPrettyJsonString()}")
        adminEventBuilder
            .realm(realm)
            .resource(ResourceType.USER)
            .operation(OperationType.ACTION)
            .resourcePath(userId)
            .detail("username", user.username)
            .detail("lastFailureIP", failureModel.lastIPFailure ?: "unknown")
            .detail("lastFailure", failureModel.lastFailure.toString())
            .detail("numLoginFailures", failureModel.numFailures.toString())
            .representation(failureModel.toJsonString())
            .success()

        return Response.ok(failureModel.toJsonString()).build()
    }



//    fun Any.toJsonString(): String {
//        return objectMapper.writeValueAsString(this)
//    }
//
//    fun Any.toPrettyJsonString(): String {
//        return prettyObjectMapper.writeValueAsString(this)
//    }

}