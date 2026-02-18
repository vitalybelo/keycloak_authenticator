package keycloak.spi.custom_resources.admin

import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.services.resources.admin.AdminEventBuilder
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator

class CustomAdminResourceProvider: AdminRealmResourceProvider {


    override fun getResource(

        keycloakSession: KeycloakSession,
        realmModel: RealmModel,
        adminPermissionEvaluator: AdminPermissionEvaluator,
        adminEventBuilder: AdminEventBuilder

    ): Any {

        return CustomAdminResource(
            keycloakSession,
            realmModel,
            adminPermissionEvaluator,
            adminEventBuilder
        )
    }

    override fun close() {
    }

}