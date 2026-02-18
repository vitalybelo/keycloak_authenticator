package keycloak.spi.custom_resources.admin

import jakarta.ws.rs.GET
import jakarta.ws.rs.POST
import jakarta.ws.rs.PUT
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import keycloak.spi.custom_resources.model.UserListDto
import keycloak.spi.jackson_mapper.toJsonString
import keycloak.spi.jackson_mapper.toPrettyJsonString
import org.eclipse.microprofile.openapi.annotations.media.Content
import org.eclipse.microprofile.openapi.annotations.media.Schema
import org.eclipse.microprofile.openapi.annotations.parameters.RequestBody
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
import org.keycloak.events.EventBuilder
import org.keycloak.events.EventType
import org.keycloak.models.cache.UserCache
import org.keycloak.services.managers.AuthenticationManager


class CustomAdminResource(

    private val session: KeycloakSession,
    private val realm: RealmModel,
    private val auth: AdminPermissionEvaluator,
    private val adminEventBuilder: AdminEventBuilder

) {

    val eventBuilder = EventBuilder(realm, session, session.context.connection)

    companion object {
        private val logger = Logger.getLogger(CustomAdminResource::class.java)
    }


    /**
     * Выполняет чтение учетных записей рабочей области realm и возвращает все username
     * @return status выполнения и экземпляр класса UserListDto
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
            ?: return Response.status(Response.Status.NOT_FOUND)
                .entity("No one users found in realm: ${realm.name}").build()

        val userCount = userList.size
        logger.info(">>>> Successfully found: $userCount users")
        val userListDto = UserListDto(userCount, userList)

        adminEventBuilder.resource(ResourceType.USER)
            .resourcePath(session.context.uri)
            .representation(userList)
            .authUser(auth.adminAuth().user)
            .operation(OperationType.ACTION)
            .detail("custom_filter", "find_all_usernames")
            .realm(realm)
            .success()

        return Response.ok(userListDto).build()
    }


    /**
     * Выполняет обновление или добавление атрибутов пользователю заданному параметром userId
     * @param userId идентификатор пользователя
     * @param attributes карта атрибутов: ключ, значение
     * @return status выполнения
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
        @RequestBody attributes: Map<String, String?>?
    ): Response {

        if (userId.isNullOrEmpty() || attributes.isNullOrEmpty())
            return Response.status(Response.Status.BAD_REQUEST).entity("Bad request").build()

        val userPermissionEvaluator = auth.users()
        userPermissionEvaluator.requireManage() // требуем роль управления

        val userModel = session.users()?.getUserById(realm, userId)
            ?: return Response.status(Response.Status.NOT_FOUND)
                .entity("User not found in realm: ${realm.name}").build()

        attributes.forEach { (key, value) ->
            val valueString = value ?: ""
            userModel.setSingleAttribute(key, valueString)
        }

        val details = mapOf(
            "action" to "update_attributes",
            "payload" to attributes.toString()
            )
        createEvent(userModel, EventType.UPDATE_PROFILE, details)
        adminEventBuilder.resource(ResourceType.USER)
            .operation(OperationType.UPDATE)
            .resourcePath(session.context.uri)
            .representation(userModel.attributes)
            .authUser(userModel)
            .realm(realm)
            .success()

        return Response.ok(userModel.attributes).build()
    }


    /**
     * Выполняет проверку наличия временной блокировки в результате многократно неверно введенных
     * логина или пароля - функционал brute force.
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
            description = "Forbidden to query realm",
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
            responseCode = "204",
            description = "Gone successfully, but user login failures absent",
            content = [Content(schema = Schema(implementation = Response::class))]
        )
    )
    @GET
    @Path("users/{userId}/login-failures")
    @Produces(MediaType.APPLICATION_JSON)
    fun getLoginFailures(@PathParam("userId") userId: String?): Response {

        logger.info(">>>> Received userId = $userId")
        if (userId.isNullOrEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Bad request").build()
        }
        val userPermissionEvaluator = auth.users()
        userPermissionEvaluator.requireQuery() // требуем роль для запроса

        val userModel = session.users().getUserById(realm, userId)
            ?: return Response.status(Response.Status.NOT_FOUND).entity("User not found in realm: ${realm.name}").build()

        logger.info(">>>> Found user: ${userModel.username}")
        val failureProvider = session.loginFailures()
        val failureModel = failureProvider?.getUserLoginFailure(realm, userModel.id)
            ?: return Response.noContent().build()

        logger.info(">>>> Login failures for user: ${userModel.username} found: ${failureModel.toPrettyJsonString()}")

        adminEventBuilder.resource(ResourceType.USER)
            .operation(OperationType.ACTION)
            .resourcePath(session.context.uri)
            .detail("username", userModel.username)
            .detail("lastFailureIP", failureModel.lastIPFailure ?: "unknown")
            .detail("lastFailure", failureModel.lastFailure.toString())
            .detail("numLoginFailures", failureModel.numFailures.toString())
            .representation(failureModel)
            .success()

        return Response.ok(failureModel.toJsonString()).build()
    }


    /**
     * Выполняет закрытие всех сессия пользователя в рабочей области realm с очисткой кэша
     * @param userId идентификатор пользователя
     * @return статус выполнения
     */
    @APIResponses(
        APIResponse(
            responseCode = "200",
            description = "User logout successful",
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
            description = "Bad request, userId is invalid",
            content = [Content(schema = Schema(implementation = Response::class))]
        ),
        APIResponse(
            responseCode = "404",
            description = "User not found",
            content = [Content(schema = Schema(implementation = Response::class))]
        )
    )
    @POST
    @Path("users/{userId}/logout")
    @Produces(MediaType.APPLICATION_JSON)
    fun logout(@PathParam("userId") userId: String?): Response {

        logger.info(">>>> Received userId = $userId")
        if (userId.isNullOrEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Bad request").build()
        }
        logger.info(">>>> Start check rights to manage Logout ")
        val userPermissionEvaluator = auth.users()
        userPermissionEvaluator.requireManage() // требуем роль для управления

        // проверяем наличие пользователя в keycloak, переданного по userId
        val userModel = session.users().getUserById(realm, userId)
            ?: return Response.status(Response.Status.NOT_FOUND).entity("User not found").build()

        // завершаем все текущие сессии пользователя для рабочей области realm
        session.sessions().getUserSessionsStream(realm, userModel)?.forEach { userSession ->
            AuthenticationManager.backchannelLogout(session, userSession, true)
        }
		// удаляем пользователя из кеша текущей рабочей области
        session.getProvider(UserCache::class.java)?.evict(realm, userModel)

        val details = mapOf(
            "payload" to "userId = $userId",
            "action" to "LOGOUT"
        )
        createEvent(userModel, EventType.LOGOUT, details)
        adminEventBuilder.resource(ResourceType.USER)
            .operation(OperationType.ACTION)
            .resourcePath(session.context.uri)
            .detail("username", userModel.username)
            .detail("clientId", session.context.client.clientId)
            .detail("realm", realm.name)
            .detail("action", "LOGOUT")
            .success()

        return Response.ok("successfully logged out").build()
    }


    /**
     * Выполняет создание пользовательского события
     * @param userModel модель пользователя Keycloak
     * @param eventType тип регистрируемого события
     */
    private fun createEvent(
        userModel: UserModel,
        eventType: EventType,
        details: Map<String, String>?
    ) {
        try {
            val userSession =
                session.sessions().getUserSessionsStream(realm, userModel).findAny()

            eventBuilder.event(eventType)
                .realm(realm)
                .user(userModel)
                .client(session.context.client)
                .ipAddress(session.context.connection.remoteAddr)

            if (userSession.isPresent) {
                eventBuilder.session(userSession.get())
            }
            details?.forEach { (key, value) ->
                eventBuilder.detail(key, value)
            }
            eventBuilder.success()

        } catch (ex: Exception) {
            logger.error(
                "Exception create event for user: ${userModel.username}, message: ${ex.message}, cause: ${ex.cause}"
            )
        }
    }


}