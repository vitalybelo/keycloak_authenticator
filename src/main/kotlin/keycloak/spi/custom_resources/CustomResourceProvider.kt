package keycloak.spi.custom_resources

import org.keycloak.events.EventBuilder
import org.keycloak.models.KeycloakSession
import org.keycloak.services.resource.RealmResourceProvider


class CustomResourceProvider(

    private val session: KeycloakSession
): RealmResourceProvider {


    override fun getResource(): Any {

        val realmModel = session.context.realm
        return CustomResource(
            session,
            realmModel,
            EventBuilder(realmModel, session, session.context.connection)
        )
    }

    override fun close() {
    }

}