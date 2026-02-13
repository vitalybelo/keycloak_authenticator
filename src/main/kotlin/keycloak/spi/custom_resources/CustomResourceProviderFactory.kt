//package keycloak.spi.custom_resources
//
//import org.keycloak.Config
//import org.keycloak.models.KeycloakSession
//import org.keycloak.models.KeycloakSessionFactory
//import org.keycloak.services.resource.RealmResourceProvider
//import org.keycloak.services.resource.RealmResourceProviderFactory
//
//class CustomResourceProviderFactory: RealmResourceProviderFactory {
//
//    companion object {
//        private const val PROVIDER_ID = "custom_resources"
//    }
//
//    override fun create(session: KeycloakSession?): RealmResourceProvider? {
//        return if (session == null) null
//                    else CustomResourceProvider(session)
//    }
//
//    override fun init(config: Config.Scope?) {
//    }
//
//    override fun postInit(keycloakSessionFactory: KeycloakSessionFactory) {
//    }
//
//    override fun close() {
//    }
//
//    override fun getId(): String {
//        return PROVIDER_ID
//    }
//}