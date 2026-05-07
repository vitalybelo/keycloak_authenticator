package keycloak.spi.custom_resources.migration

import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.services.resources.admin.AdminEventBuilder
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator

/**
 * Класс админ ресурс провайдера, предназначен для вызова класса реализации api branch миграция
 * @author Belotserkovskii Vitalii (c) 07.05.2026
 */
class BranchMigrationResourceProvider: AdminRealmResourceProvider {

    override fun getResource(
        session: KeycloakSession,
        realm: RealmModel,
        auth: AdminPermissionEvaluator,
        adminEvent: AdminEventBuilder
    ): Any {
        return BranchMigrationResource(session, realm, auth, adminEvent)
    }

    override fun close() {}
}