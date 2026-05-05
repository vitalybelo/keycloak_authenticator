package keycloak.spi.custom_resources.admin

import org.keycloak.events.EventBuilder
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.services.resources.admin.AdminEventBuilder
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator

class CustomAdminResourceProvider: AdminRealmResourceProvider {


    override fun getResource(

        session: KeycloakSession,
        realm: RealmModel,
        adminPermissionEvaluator: AdminPermissionEvaluator,
        adminEventBuilder: AdminEventBuilder

    ): Any {

        return CustomAdminResource(
            session,
            realm,
            adminPermissionEvaluator,
            adminEventBuilder,
            EventBuilder(realm, session, session.context.connection)
        )
    }

    override fun close() {
    }

}