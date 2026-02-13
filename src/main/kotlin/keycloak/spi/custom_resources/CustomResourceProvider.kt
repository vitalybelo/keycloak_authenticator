//package keycloak.spi.custom_resources
//
//import jakarta.ws.rs.GET
//import jakarta.ws.rs.Path
//import jakarta.ws.rs.Produces
//import jakarta.ws.rs.core.MediaType
//import jakarta.ws.rs.core.Response
//import org.eclipse.microprofile.openapi.annotations.Operation
//import org.eclipse.microprofile.openapi.annotations.enums.SchemaType
//import org.eclipse.microprofile.openapi.annotations.media.Content
//import org.eclipse.microprofile.openapi.annotations.media.Schema
//import org.eclipse.microprofile.openapi.annotations.responses.APIResponse
//import org.keycloak.models.KeycloakSession
//import org.keycloak.services.resource.RealmResourceProvider
//
//
//class CustomResourceProvider(
//
//    private val session: KeycloakSession
//): RealmResourceProvider {
//
//
//    @GET
//    @Path("hello")
//    @Produces(MediaType.APPLICATION_JSON)
//    @Operation(
//        summary = "Public hello endpoint",
//        description = "This endpoint returns hello and the name of the requested realm."
//    )
//    @APIResponse(
//        responseCode = "200",
//        description = "",
//        content = [Content(schema = Schema(implementation = Response::class, type = SchemaType.OBJECT))]
//    )
//    fun helloAnonymous(): Response {
//        val realmName = session.context.realm.name
//        val response = mapOf<String, String>("hello" to  realmName)
//        return Response.ok(response).build()
//    }
//
//
//
//
//
//
//    override fun getResource(): Any {
//        return this
//    }
//
//    override fun close() {
//    }
//
//}