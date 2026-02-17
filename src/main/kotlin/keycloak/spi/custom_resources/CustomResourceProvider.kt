package keycloak.spi.custom_resources

import org.keycloak.events.EventBuilder
import org.keycloak.models.KeycloakSession
import org.keycloak.services.resource.RealmResourceProvider


class CustomResourceProvider(

    private val session: KeycloakSession
): RealmResourceProvider {


    override fun getResource(): Any {

        return CustomResource(
            session,
            session.context.realm,
            EventBuilder(
                session.context.realm,
                session,
                session.context.connection
            )
        )
    }

    override fun close() {
    }

}