package keycloak.spi.custom_resources

import jakarta.ws.rs.*
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import io.vertx.core.impl.logging.LoggerFactory
import org.eclipse.microprofile.openapi.annotations.Operation
import org.eclipse.microprofile.openapi.annotations.enums.SchemaType
import org.eclipse.microprofile.openapi.annotations.media.Content
import org.eclipse.microprofile.openapi.annotations.media.Schema
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse
import org.keycloak.models.KeycloakSession
import org.keycloak.services.managers.AppAuthManager.BearerTokenAuthenticator
import org.keycloak.services.managers.AuthenticationManager
import org.keycloak.services.managers.BruteForceProtector
import org.keycloak.services.resource.RealmResourceProvider


class CustomResourceProvider(

    private val session: KeycloakSession
): RealmResourceProvider {

    private val logger = LoggerFactory.getLogger(CustomResourceProvider::class.java)
    companion object {
        private val requiredScopes: List<String> = listOf("openid")
    }


    @GET
    @Path("hello")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
        summary = "Public hello endpoint",
        description = "This endpoint returns hello and the name of the requested realm."
    )
    @APIResponse(
        responseCode = "200",
        description = "",
        content = [Content(schema = Schema(implementation = Response::class, type = SchemaType.OBJECT))]
    )
    fun helloAnonymous(): Response {

        val realmName = session.context.realm.name
        val response = mapOf("hello" to  realmName)
        return Response.ok(response).build()
    }

    @GET
    @Path("hello-auth")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
        summary = "Authenticated hello endpoint",
        description = "This endpoint returns hello and user name if authenticated."
    )
    fun helloAuthenticated(): Response? {

        // проверяем аутентификацию
        val auth = isAuthenticationProvided() ?: throw NotAuthorizedException("Bearer")
        // проверяем, если ли утверждение openid в scope токена пользователя
        if (!isScopeProvided(auth)) throw ForbiddenException("Forbidden")

        val user = session.context.user
        val realm = session.context.realm

        // верхнеуровневая проверка brute force: заблокирован или нет
        // новый токен заблокированным пользователям не выдается, а по старому, мы выкинем тут
        val protector = session.getProvider(BruteForceProtector::class.java)
        if (protector.isTemporarilyDisabled(session, realm, user)) {
            logger.info(">>>> user temporarily disabled - access denied")
            throw ForbiddenException("Access denied")
        }

        return Response.ok(mapOf("hello" to auth.user.username)).build()
    }


    @GET
    @Path("brute-force")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
        summary = "Authenticated brute force protector endpoint",
        description = "This endpoint returns User Login Failure Model if authenticated."
    )
    fun bruteForceProtector(): Response {

        // проверяем аутентификацию
        val auth = isAuthenticationProvided() ?: throw NotAuthorizedException("Bearer")
        // проверяем, если ли утверждение openid в scope токена пользователя
        if (!isScopeProvided(auth)) throw ForbiddenException("Forbidden")

        val user = session.context.user
        val realm = session.context.realm

        // низкоуровневая проверка - можем прочитать запись неуспешных логинов
        val failureProvider = session.loginFailures()
        val failureModel = failureProvider.getUserLoginFailure(realm, user.id)
        if (failureModel != null) {
            logger.info("""
                Login Failures model:
                | numFailures = ${failureModel.numFailures}
                | lastFailure = ${failureModel.lastFailure}
                | lastIp = ${failureModel.lastIPFailure}
            """.trimIndent())
            return Response.ok(failureModel).build()
        }
        logger.info(">>>> No login failures recorded")
        return Response.status(404).entity("Not found Login Failures for: ${user.username}").build()
    }


    /**
     * Выполняет проверку наличия и годности аутентификации запроса (токена доступа)
     * @return экземпляр класса AuthResult
     */
    fun isAuthenticationProvided(): AuthenticationManager.AuthResult? {

        BearerTokenAuthenticator(session).authenticate()?.let { authentication ->
            if (!authentication.token.isExpired) return authentication
        }
        logger.info(">>>> Access token expired")
        return null
    }

    /**
     * Проверяет наличие требуемых для авторизации scope в токене доступа
     * @return true если запрос авторизирован
     */
    fun isScopeProvided(auth: AuthenticationManager.AuthResult): Boolean {

        val tokenScope = auth.token.scope ?: return false
        val isFound = requiredScopes.stream().allMatch { tokenScope.contains(it) }
        return isFound
    }


    override fun getResource(): Any {
        return this
    }

    override fun close() {
    }

}