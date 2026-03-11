@file:Suppress("DuplicatedCode")

package keycloak.spi.custom_resources.admin

import jakarta.ws.rs.BadRequestException
import jakarta.ws.rs.NotFoundException
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
import keycloak.spi.constants.Constants
import keycloak.spi.custom_resources.model.LoginFailureDto
import keycloak.spi.custom_resources.model.ResponseDto
import keycloak.spi.custom_resources.model.UserListDto
import keycloak.spi.jackson_mapper.toJsonString
import keycloak.spi.utils.getCacheKey
import keycloak.spi.utils.getInfinispanLoginAttemptCache
import keycloak.spi.jackson_mapper.toPrettyJsonString
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
        private const val MAX_COUNT = 1000
        private const val PAGE_SIZE = 100
        private const val ACTION_UNLOCK_USER = "UNLOCK_USER"
        private const val ACTION_LOGOUT = "LOGOUT"
    }


    /**
     * Выполняет чтение учетных записей рабочей области realm и возвращает все username
     * @return status выполнения и экземпляр класса UserListDto
     */
    @APIResponses(value = [
        APIResponse(responseCode = "200", description = "Username list received"),
        APIResponse(responseCode = "401", description = "Unauthorized"),
        APIResponse(responseCode = "403", description = "Forbidden to manage realm"),
        APIResponse(responseCode = "404", description = "Users absent")
    ])
    @GET
    @Path("users/list")
    @Produces(MediaType.APPLICATION_JSON)
    fun getListOfUsernames(
        @QueryParam("page") pageSize: Int,
        @QueryParam("max") maxCount: Int
    ): Response {

        auth.users().requireQuery() // требуем роль для запроса

        val page = if (pageSize <= 0) PAGE_SIZE else pageSize
        val max = if (maxCount <= 0) MAX_COUNT else maxCount
        logger.info(">>>> Usernames list procedure started for page = $page, max = $max")

        val count = session.users().getUsersCount(realm)
        if (count <= 0) {
            logger.info(">>>> Not found users")
            return Response.status(Response.Status.NOT_FOUND)
                .entity(ResponseDto.error("Users absent in realm \"$realm\"")).build()
        }
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

        logger.info(">>>> Successfully found: ${users.size} users in realm: \"${realm.name}\"")
        val userListDto = UserListDto(users.size, users)

        adminEventBuilder.resource(ResourceType.USER)
            .detail("custom_filter", "find all usernames")
            .resourcePath(session.context.uri)
            .operation(OperationType.ACTION)
            .authUser(auth.adminAuth()?.user)
            .realm(realm)
            .success()

        return Response.ok()
            .entity(ResponseDto.success("Found and filtered", userListDto)).build()
    }


    /**
     * Выполняет обновление или добавление атрибутов пользователю заданному параметром userId
     * @param userId идентификатор пользователя
     * @param attributes карта атрибутов: ключ, значение
     * @return status выполнения
     */
    @APIResponses(value = [
        APIResponse(responseCode = "200", description = "Success updated attributes"),
        APIResponse(responseCode = "401", description = "Unauthorized"),
        APIResponse(responseCode = "403", description = "Forbidden to manage realm"),
        APIResponse(responseCode = "400", description = "Bad request. UserId or Attribute Map is invalid"),
        APIResponse(responseCode = "404", description = "User Not Found")
    ])
    @PUT
    @Path("users/{userId}/attributes")
    @Produces(MediaType.APPLICATION_JSON)
    fun updateUserAttributes(
        @PathParam("userId") userId: String?,
        @RequestBody attributes: Map<String, String?>?
    ): Response {

        auth.users().requireManage() // требуем роль управления
        val userModel = validateUser(userId, "change user attributes")
        if (attributes.isNullOrEmpty()) throw BadRequestException("User attributes absent in request")

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
            .entity(ResponseDto.success("attributes updated", userModel.attributes)).build()
    }


    /**
     * Выполняет проверку наличия временной блокировки в результате многократно неверно введенных
     * логина или пароля - функционал brute force.
     * @param userId идентификатор пользователя
     */
    @APIResponses(value = [
        APIResponse(responseCode = "200", description = "Login failures found"),
        APIResponse(responseCode = "401", description = "Unauthorized"),
        APIResponse(responseCode = "403", description = "Forbidden to query realm"),
        APIResponse(responseCode = "400", description = "Bad request, userId is invalid"),
        APIResponse(responseCode = "404", description = "User not found"),
        APIResponse(responseCode = "202", description = "User login failures absent")
    ])
    @GET
    @Path("users/{userId}/login-failures")
    @Produces(MediaType.APPLICATION_JSON)
    fun getLoginFailures(@PathParam("userId") userId: String?): Response {

        auth.users().requireQuery() // требуем роль для запроса
        val user = validateUser(userId, "to check login failures")

        val username = user.username
        logger.info(">>>> User: \"$username\" found successfully")
        val failureProvider = session.loginFailures()
        val userFailureModel = failureProvider.getUserLoginFailure(realm, user.id)
            ?: return Response
                .status(Response.Status.ACCEPTED)
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


    /**
     * Выполняет чтение из кэша infinispan записи об ошибках входа для пользователя, заданного параметром.
     * @param userId идентификатор пользователя, для которого выполняется проверка
     * @return запись об ошибках входа, если они существуют (иначе 202 и текст)
     */
    @APIResponses(value = [
        APIResponse(responseCode = "200", description = "Login failures found"),
        APIResponse(responseCode = "401", description = "Unauthorized"),
        APIResponse(responseCode = "403", description = "Forbidden to query realm"),
        APIResponse(responseCode = "400", description = "Bad request, userId is invalid"),
        APIResponse(responseCode = "404", description = "User not found"),
        APIResponse(responseCode = "202", description = "User login failures absent")
    ])
    @GET
    @Path("users/{userId}/login-attempt")
    @Produces(MediaType.APPLICATION_JSON)
    fun getLoginAttempt(@PathParam("userId") userId: String?): Response {

        auth.users().requireQuery() // требуем роль для запроса
        val user = validateUser(userId, "to check login attempts")

        val username = user.username ?: Constants.ANONYMOUS
        val cacheKey = getCacheKey(realm.id, userId!!)
        val cache = getInfinispanLoginAttemptCache(session)

        val loginAttempt = cache[cacheKey]
            ?: return Response
                .status(Response.Status.ACCEPTED)
                .entity(ResponseDto.success("Login errors absent for user = $username")).build()

        logger.info(">>>> User = $username :: login errors found: ${loginAttempt.toJsonString()}")
        adminEventBuilder.resource(ResourceType.USER)
            .resourcePath(session.context.uri)
            .operation(OperationType.ACTION)
            .detail("username", username)
            .detail("failures", loginAttempt.failures.size.toString())
            .detail("isBlocked", loginAttempt.blockType.isBlocked().toString())
            .representation(loginAttempt)
            .authUser(auth.adminAuth()?.user)
            .realm(realm)
            .success()

        return Response
            .ok(ResponseDto.success("login errors registered", loginAttempt)).build()
    }


    /**
     * Обнуляет для заданного параметром пользователя все предыдущие ошибки входа (если они были)
     * @param userId идентификатор пользователя, для которого выполняется проверка
     * @return экземпляр класса из infinispan или 202
     */
    @APIResponses(value = [
        APIResponse(responseCode = "200", description = "Login failures deleted"),
        APIResponse(responseCode = "401", description = "Unauthorized"),
        APIResponse(responseCode = "403", description = "Forbidden to manage realm"),
        APIResponse(responseCode = "400", description = "Bad request, userId is invalid"),
        APIResponse(responseCode = "404", description = "User not found"),
        APIResponse(responseCode = "202", description = "User login failures absent")
    ])
    @DELETE
    @Path("users/{userId}/login-attempt")
    @Produces(MediaType.APPLICATION_JSON)
    fun deleteLoginAttempt(@PathParam("userId") userId: String?): Response {

        auth.users().requireManage() // требуем роль для управления
        val user = validateUser(userId, "to delete login attempts")

        val cacheKey = getCacheKey(realm.id, userId!!)
        val cache = getInfinispanLoginAttemptCache(session)

        val username = user.username ?: Constants.ANONYMOUS
        val loginAttempt = cache.remove(cacheKey)
            ?: return Response
                .status(Response.Status.ACCEPTED)
                .entity(ResponseDto.error("Login attempts absent for user = $username")).build()

        val details = mapOf(
            "action" to ACTION_UNLOCK_USER,
            "userId" to user.id
        )
        createEvent(user, EventType.UPDATE_PROFILE, details)
        adminEventBuilder.resource(ResourceType.USER)
            .resourcePath(session.context.uri)
            .operation(OperationType.ACTION)
            .detail("username", username)
            .detail("action", ACTION_UNLOCK_USER)
            .authUser(auth.adminAuth()?.user)
            .realm(realm)
            .success()


        logger.info(">>>> Login attempt reset for user = ${user.username}")
        return Response.ok(ResponseDto.success("last record received", loginAttempt)).build()
    }


    /**
     * Выполняет проверку наличия временной блокировки в результате многократно неверно введенных
     * логина или пароля - функционал brute force.
     * @param userId идентификатор пользователя
     */
    @APIResponses(value = [
        APIResponse(responseCode = "200", description = "Login failures deleted"),
        APIResponse(responseCode = "401", description = "Unauthorized"),
        APIResponse(responseCode = "403", description = "Forbidden to manage realm"),
        APIResponse(responseCode = "400", description = "Bad request, userId is invalid"),
        APIResponse(responseCode = "404", description = "User not found"),
        APIResponse(responseCode = "202", description = "User login failures absent")
    ])
    @DELETE
    @Path("users/{userId}/login-failures")
    @Produces(MediaType.APPLICATION_JSON)
    fun deleteLoginFailures(@PathParam("userId") userId: String?): Response {

        auth.users().requireManage() // требуем роль для управления
        val user = validateUser(userId, "to delete temporary lock")

        val username = user.username ?: Constants.ANONYMOUS
        val failureProvider = session.loginFailures()
        failureProvider.getUserLoginFailure(realm, user.id)
            ?: return Response
                .status(Response.Status.ACCEPTED)
                .entity(ResponseDto.success("Temporary locks absent for user = $username")).build()

        failureProvider.removeUserLoginFailure(realm, user.id)
        logger.info(">>>> Temporary lock was successfully deleted for user = $username")

        val details = mapOf(
            "action" to ACTION_UNLOCK_USER,
            "userId" to user.id
        )
        createEvent(user, EventType.UPDATE_PROFILE, details)
        adminEventBuilder.resource(ResourceType.USER)
            .resourcePath(session.context.uri)
            .operation(OperationType.ACTION)
            .detail("username", user.username)
            .detail("action", ACTION_UNLOCK_USER)
            .authUser(auth.adminAuth()?.user)
            .realm(realm)
            .success()

        return Response
            .ok(ResponseDto.success("user: ${user.username} unlocked successfully")).build()
    }


    /**
     * Выполняет закрытие всех сессия пользователя в рабочей области realm с очисткой кэша
     * @param userId идентификатор пользователя
     * @return статус выполнения
     */
    @APIResponses(value = [
        APIResponse(responseCode = "200", description = "User logout successful"),
        APIResponse(responseCode = "401", description = "Unauthorized"),
        APIResponse(responseCode = "403", description = "Forbidden to manage realm"),
        APIResponse(responseCode = "400", description = "Bad request, userId is invalid"),
        APIResponse(responseCode = "404", description = "User not found")
    ])
    @POST
    @Path("users/{userId}/logout")
    @Produces(MediaType.APPLICATION_JSON)
    fun logout(@PathParam("userId") userId: String?): Response {

        auth.users().requireManage() // требуем роль для управления
        val user = validateUser(userId, "to logout")

        // завершаем все текущие сессии пользователя для рабочей области realm
        session.sessions().removeUserSessions(realm, user)

		// удаляем пользователя из кеша текущей рабочей области
        session.getProvider(UserCache::class.java)?.evict(realm, user)

        val username = user.username ?: Constants.ANONYMOUS
        val details = mapOf(
            "payload" to "userId = $userId",
            "action" to ACTION_LOGOUT
        )
        createEvent(user, EventType.LOGOUT, details)
        adminEventBuilder.resource(ResourceType.USER)
            .operation(OperationType.ACTION)
            .resourcePath(session.context.uri)
            .detail("clientId", session.context.client.clientId)
            .detail("username", username)
            .detail("realm", realm.name)
            .detail("action", ACTION_LOGOUT)
            .authUser(auth.adminAuth()?.user)
            .realm(realm)
            .success()

        return Response.ok()
            .entity(ResponseDto.success("All sessions terminated for = $username")).build()
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

    /**
     * Проверяет наличие в keycloak заданного параметром пользователя
     * @param userId идентификатор пользователя
     * @return экземпляр класса UserModel
     */
    private fun validateUser(userId: String?, message: String?): UserModel {

        logger.info(">>>> Received request :: $message :: for userId = $userId")
        if (userId.isNullOrBlank()) {
            throw BadRequestException("Bad request userId = <$userId>")
        }

        val user = session.users().getUserById(realm, userId)
            ?: throw NotFoundException("user userId = <$userId> not found")

        logger.info(">>>> User \"${user.username}\" found successfully")
        return user
    }

}