@file:Suppress("DuplicatedCode")

package keycloak.spi.custom_resources.admin

import jakarta.ws.rs.DELETE
import jakarta.ws.rs.GET
import jakarta.ws.rs.POST
import jakarta.ws.rs.PUT
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import keycloak.spi.custom_resources.model.LoginFailureDto
import keycloak.spi.custom_resources.model.ResponseDto
import keycloak.spi.custom_resources.model.UserListDto
import keycloak.spi.getCacheKey
import keycloak.spi.getInfinispanLoginAttemptCache
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
import org.jboss.logging.Logger
import org.keycloak.events.EventBuilder
import org.keycloak.events.EventType
import org.keycloak.models.cache.UserCache


class CustomAdminResource(

    private val session: KeycloakSession,
    private val realm: RealmModel,
    private val auth: AdminPermissionEvaluator,
    private val adminEventBuilder: AdminEventBuilder,
    private val eventBuilder: EventBuilder

) {

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
    fun getListOfUsernames(
        @QueryParam("page") pageSize: Int,
        @QueryParam("max") maxCount: Int
    ): Response {

        val page = if (pageSize == 0) 100 else pageSize
        val max = if (maxCount == 0) 500_000 else maxCount

        logger.info(">>>> Usernames list procedure started for page = $page, max = $max")
        val userPermissionEvaluator = auth.users()
        userPermissionEvaluator.requireQuery() // требуем роль для запроса

        val count = session.users().getUsersCount(realm)
        if (count <= 0) {
            return Response.status(Response.Status.NOT_FOUND)
                .entity(ResponseDto.error("Users absent in realm $realm")).build()
        }
        logger.info(">>>> Totally found: $count users")
        val limit = minOf(count, max)

        var offset = 0
        val users = mutableListOf<String>()
        logger.info(">>>> Start produce with limit = $limit")

        while (users.size < limit) {

            val left = limit - users.size
            val batch = minOf(left, page)

            val userModels = session.users()
                .searchForUserStream(realm, emptyMap(), offset, batch)
                .toList()
            if (userModels.isEmpty()) break

            val usernames = userModels.filter { it.serviceAccountClientLink == null }.map { it.username }
            if (usernames.isNotEmpty()) {
                users.addAll(usernames)
            }

            if (userModels.size < batch) break
            offset += batch
        }

        logger.info(">>>> Successfully found: ${users.size} users in realm: ${realm.name}")
        val userListDto = UserListDto(users.size, users)

        adminEventBuilder.resource(ResourceType.USER)
            .detail("custom_filter", "find all usernames")
            .resourcePath(session.context.uri)
            .operation(OperationType.ACTION)
            .authUser(auth.adminAuth()?.user)
            .realm(realm)
            .success()

        return Response.ok()
            .entity(ResponseDto.success("Users found and filtered", userListDto))
            .build()
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

        if (userId.isNullOrBlank() || attributes.isNullOrEmpty()) {
            return Response
                .status(Response.Status.BAD_REQUEST)
                .entity(ResponseDto.error("Bad request userId = $userId, attributes = $attributes")).build()
        }
        auth.users().requireManage() // требуем роль управления

        val userModel = session.users().getUserById(realm, userId)
            ?: return Response.status(Response.Status.NOT_FOUND).entity("User not found").build()

        attributes.forEach { (key, value) ->
            if (value.isNullOrBlank()) {
                userModel.removeAttribute(key)
            } else {
                userModel.setSingleAttribute(key, value)
            }
        }

        val updatedKeys = attributes.keys.joinToString(separator = ",")
        val details = mapOf(
            "action" to "update attributes",
            "payload" to attributes.toString()
            )
        createEvent(userModel, EventType.UPDATE_PROFILE, details)
        adminEventBuilder.resource(ResourceType.USER)
            .resourcePath(session.context.uri)
            .operation(OperationType.UPDATE)
            .representation(attributes)
            .detail("updated_keys", updatedKeys)
            .authUser(auth.adminAuth()?.user)
            .realm(realm)
            .success()

        return Response.ok()
            .entity(ResponseDto.success("attributes updated", userModel.attributes))
            .build()
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

        logger.info(">>>> Received request to check login failures for userId = $userId")
        if (userId.isNullOrBlank()) {
            return Response
                .status(Response.Status.BAD_REQUEST)
                .entity(ResponseDto.error("bad request userId = $userId")).build()
        }

        auth.users().requireQuery() // требуем роль для запроса

        val userModel = session.users().getUserById(realm, userId)
            ?: return Response
                .status(Response.Status.NOT_FOUND)
                .entity(ResponseDto.error("user userId = $userId not found")).build()

        val username = userModel.username
        logger.info(">>>> User: \"$username\" found successfully")
        val failureProvider = session.loginFailures()
        val userFailureModel = failureProvider.getUserLoginFailure(realm, userModel.id)
            ?: return Response
                .status(Response.Status.NO_CONTENT)
                .entity(ResponseDto.success("user $username has no locks")).build()

        val failureModel = LoginFailureDto.fromModel(userFailureModel)
        logger.info(">>>> Login failures for user \"$username\" found:\n ${failureModel.toPrettyJsonString()}")

        adminEventBuilder.resource(ResourceType.USER)
            .resourcePath(session.context.uri)
            .operation(OperationType.ACTION)
            .detail("username", username)
            .detail("lastFailureIP", failureModel.lastIPFailure)
            .detail("lastFailure", failureModel.lastFailure.toString())
            .detail("numLoginFailures", failureModel.numFailures.toString())
            .representation(failureModel)
            .authUser(auth.adminAuth()?.user)
            .realm(realm)
            .success()

        return Response
            .ok(ResponseDto.success("login failures observed",failureModel))
            .build()
    }


    @GET
    @Path("users/{userId}/login-attempt")
    @Produces(MediaType.APPLICATION_JSON)
    fun getLoginAttempt(@PathParam("userId") userId: String?): Response {

        logger.info(">>>> Received request to check login attempts for userId = $userId")
        if (userId.isNullOrBlank()) {
            return Response
                .status(Response.Status.BAD_REQUEST)
                .entity(ResponseDto.error("bad request userId = $userId")).build()
        }

        auth.users().requireQuery() // требуем роль для запроса

        val user = session.users().getUserById(realm, userId)
            ?: return Response
                .status(Response.Status.NOT_FOUND)
                .entity(ResponseDto.error("user userId = $userId not found")).build()

        logger.info(">>>> User \"${user.username}\" found successfully")
        val cacheKey = getCacheKey(realm.id, userId)
        val cache = getInfinispanLoginAttemptCache(session)

        val loginAttempt = cache[cacheKey]
        if (loginAttempt != null) {

            logger.info(">>>> User = ${user.username} :: login errors found: $loginAttempt")
            return Response.ok(ResponseDto.success("login errors found", loginAttempt)).build()
        }
        return Response
            .status(Response.Status.NOT_FOUND)
            .entity(ResponseDto.error("Login errors not found for user = ${user.username}")).build()
    }


    @DELETE
    @Path("users/{userId}/login-attempt")
    @Produces(MediaType.APPLICATION_JSON)
    fun deleteLoginAttempt(@PathParam("userId") userId: String?): Response {

        logger.info(">>>> Received request to delete login attempts for userId = $userId")
        if (userId.isNullOrBlank()) {
            return Response
                .status(Response.Status.BAD_REQUEST)
                .entity(ResponseDto.error("bad request userId = $userId")).build()
        }

        auth.users().requireManage() // требуем роль для управления

        val user = session.users().getUserById(realm, userId)
            ?: return Response
                .status(Response.Status.NOT_FOUND)
                .entity(ResponseDto.error("user userId = $userId not found")).build()

        val cacheKey = getCacheKey(realm.id, userId)
        val cache = getInfinispanLoginAttemptCache(session)

        if (cache.containsKey(cacheKey)) {

            logger.info(">>>> Login attempt found for user = ${user.username}")
            val loginAttempt = cache.remove(cacheKey)
            if (loginAttempt != null) {
                logger.info(">>>> Login attempt: $loginAttempt :: reset")
                return Response
                    .ok(ResponseDto.success("last record in body", loginAttempt)).build()
            }
        }
        return Response
            .status(Response.Status.NOT_FOUND)
            .entity(ResponseDto.error("Login attempts not found for user = ${user.username}")).build()
    }


    /**
     * Выполняет проверку наличия временной блокировки в результате многократно неверно введенных
     * логина или пароля - функционал brute force.
     * @param userId идентификатор пользователя
     */
    @APIResponses(
        APIResponse(
            responseCode = "200",
            description = "Login failures deleted",
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
            description = "Gone, user login failures absent",
            content = [Content(schema = Schema(implementation = Response::class))]
        )
    )
    @DELETE
    @Path("users/{userId}/login-failures")
    @Produces(MediaType.APPLICATION_JSON)
    fun deleteLoginFailures(@PathParam("userId") userId: String?): Response {

        logger.info(">>>> Received request to unlock userId = $userId")
        if (userId.isNullOrBlank()) {
            return Response
                .status(Response.Status.BAD_REQUEST)
                .entity(ResponseDto.error("bad request userId = $userId")).build()
        }

        auth.users().requireManage() // требуем роль для управления

        val userModel = session.users().getUserById(realm, userId)
            ?: return Response
                .status(Response.Status.NOT_FOUND)
                .entity(ResponseDto.error("user by userId = $userId not found")).build()

        logger.info(">>>> User: ${userModel.username} found successfully")

        val failureProvider = session.loginFailures()
        failureProvider.getUserLoginFailure(realm, userModel.id)
            ?: return Response
                .status(Response.Status.NO_CONTENT)
                .entity(ResponseDto.success("user userId = $userId has no locks")).build()

        failureProvider.removeUserLoginFailure(realm, userModel.id)
        logger.info(">>>> User ${userModel.username} has been successfully unlocked")

        val details = mapOf(
            "action" to "UNLOCK_USER",
            "userId" to userModel.id
        )
        createEvent(userModel, EventType.UPDATE_PROFILE, details)
        adminEventBuilder.resource(ResourceType.USER)
            .resourcePath(session.context.uri)
            .operation(OperationType.ACTION)
            .detail("username", userModel.username)
            .detail("action", "UNLOCK_USER")
            .authUser(auth.adminAuth()?.user)
            .realm(realm)
            .success()

        return Response
            .ok(ResponseDto.success("user: ${userModel.username} unlocked successfully"))
            .build()
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

        logger.info(">>>> Received request with userId = $userId")
        if (userId.isNullOrEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(ResponseDto.error("bad request userId = $userId")).build()
        }
        logger.info(">>>> Start check rights to manage Logout ")
        auth.users().requireManage() // требуем роль для управления

        // проверяем наличие пользователя в keycloak, переданного по userId
        val userModel = session.users().getUserById(realm, userId)
            ?: return Response.status(Response.Status.NOT_FOUND)
                .entity(ResponseDto.error("user with id = $userId not found")).build()

        // завершаем все текущие сессии пользователя для рабочей области realm
        session.sessions().removeUserSessions(realm, userModel)

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
            .detail("clientId", session.context.client.clientId)
            .detail("username", userModel.username)
            .detail("realm", realm.name)
            .detail("action", "LOGOUT")
            .authUser(auth.adminAuth()?.user)
            .realm(realm)
            .success()

        return Response.ok()
            .entity(ResponseDto.success("user logged out from all sessions")).build()
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
            eventBuilder.event(eventType)
                .realm(realm)
                .user(userModel)
                .client(session.context.client)
                .ipAddress(session.context.connection.remoteAddr)

            session.context.userSession?.let { userSessionModel ->
                eventBuilder.session(userSessionModel)
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