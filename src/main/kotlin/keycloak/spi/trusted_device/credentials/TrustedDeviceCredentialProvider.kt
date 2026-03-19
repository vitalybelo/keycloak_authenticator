package keycloak.spi.trusted_device.credentials

import keycloak.spi.trusted_device.toTrustedDeviceModel
import org.keycloak.credential.*
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel


class TrustedDeviceCredentialProvider(
    private val session: KeycloakSession
) : CredentialProvider<TrustedDeviceCredentialModel>, CredentialInputValidator {

    override fun getType(): String = TrustedDeviceCredentialModel.TYPE

    // --- Методы CredentialProvider ---

    override fun createCredential(
        realm: RealmModel,
        user: UserModel,
        credentialModel: TrustedDeviceCredentialModel
    ): CredentialModel = user.credentialManager().createStoredCredential(credentialModel)

    override fun deleteCredential(
        realm: RealmModel,
        user: UserModel,
        credentialId: String
    ): Boolean = user.credentialManager().removeStoredCredentialById(credentialId)

    override fun getCredentialFromModel(model: CredentialModel): TrustedDeviceCredentialModel {
        return model.toTrustedDeviceModel()
    }

    override fun getCredentialTypeMetadata(context: CredentialTypeMetadataContext): CredentialTypeMetadata {
        return CredentialTypeMetadata.builder()
            .type(type)
            .category(CredentialTypeMetadata.Category.TWO_FACTOR)
            .displayName("Trusted Device")
            .helpText("Device trusted to bypass 2FA")
            .removeable(true) // позволяет пользователю удалять устройства в личном кабинете Keycloak
            .build(session)
    }

    // --- Методы CredentialInputValidator ---

    override fun supportsCredentialType(credentialType: String): Boolean {
        return type == credentialType
    }

    override fun isConfiguredFor(realm: RealmModel, user: UserModel, credentialType: String): Boolean {
        if (!supportsCredentialType(credentialType)) return false
        // проверяем, есть ли у пользователя хотя бы одно сохраненное устройство
        return user.credentialManager()
            .getStoredCredentialsByTypeStream(credentialType)
            .findAny()
            .isPresent
    }

    override fun isValid(
        realm: RealmModel,
        user: UserModel,
        credentialInput: CredentialInput
    ): Boolean {

        if (credentialInput.type != type) return false

        // в качестве challengeResponse мы будем передавать fingerprint из cookie
        val fingerprintToCheck = credentialInput.challengeResponse

        // достаем все устройства пользователя и ищем совпадение
        val devices = user.credentialManager().getStoredCredentialsByTypeStream(type)
        return devices.anyMatch { model ->
            val trustedDevice = getCredentialFromModel(model)
            trustedDevice.deviceFingerprint == fingerprintToCheck
        }
    }
}