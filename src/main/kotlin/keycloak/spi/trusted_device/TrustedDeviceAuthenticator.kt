package keycloak.spi.trusted_device

import keycloak.spi.trusted_device.TrustedDeviceCredentialModel.Companion.toTrustedDeviceModel
import org.jboss.logging.Logger
import org.keycloak.TokenVerifier
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.Authenticator
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.representations.JsonWebToken

class TrustedDeviceAuthenticator(private val session: KeycloakSession) : Authenticator {

    companion object {
        private val logger = Logger.getLogger(TrustedDeviceAuthenticator::class.java.name)
        const val CREDENTIAL_TYPE = "trusted-device"
    }

    override fun authenticate(context: AuthenticationFlowContext) {

        val trustedDeviceConfig = TrustedDeviceConfig.init(context)
        if (trustedDeviceConfig.isDeleteOn) {
            logger.warn(">>>> Delete Trusted Device fingerprint cookie for user = ${context.user?.username}")
            context.clearDeviceCookie()
            context.attempted()
            return
        }
        if (!trustedDeviceConfig.isSwitchOn) {
            logger.warn(">>>> Trusted Device Authenticator disabled")
            context.attempted()
            return
        }
        val cookie = context.cookie()
        if (cookie == null) {
            logger.warn(">>>> No trusted device fingerprint could be found. 2FA proceed")
            context.attempted()
            return
        }

        try {
            val verifier = TokenVerifier.create(cookie.value, JsonWebToken::class.java)

            if (!verifier.verifySignature(session, context.realm)) {
                logger.warn(">>> Token signature verification failed or key not found. 2FA proceed.")
                context.clearDeviceCookie()
                context.attempted()
                return
            }
            val token = verifier.token
            val deviceFingerprint = token.subject

            // Сверяем fingerprint с сохраненными устройствами пользователя
            if (isDeviceTrusted(context.user, deviceFingerprint)) {
                context.success() // Устройство доверенное, пропускаем 2FA!
            } else {
                logger.warn(">>>> Device fingerprint not found in DB (possibly removed). Clearing cookie.")
                context.clearDeviceCookie() // Устройство удалили из базы, чистим cookie
                context.attempted()
            }

        } catch (e: Exception) {
            logger.error(">>>> Exception message = ${e.message}, cause = ${e.cause}")
            context.attempted()
        }
    }

    /**
     * В Keycloak метод action() никогда не должен оставаться без ответа (bug)
     * Если по какой-то причине (например, кнопка "Назад" в браузере) сюда прилетит POST-запрос.
     * Если метод action() пустой, статус остается null. Keycloak видит null и моментально бросает
     * внутреннюю ошибку сервера — AuthenticationFlowException("Authenticator did not set flow status")
     * Так что здесь, просто передаем управление следующему шагу Alternative.
     */
    override fun action(context: AuthenticationFlowContext) {
        logger.warn(">>>> TrustedDeviceAuthenticator received an unexpected action submit. Skipping to next.")
        context.attempted()
    }


    private fun isDeviceTrusted(user: UserModel, fingerprintToCheck: String): Boolean {
        return user.credentialManager()
            .getStoredCredentialsByTypeStream(CREDENTIAL_TYPE)
            .anyMatch { credentialModel ->
                try {
                    val trustedDevice = credentialModel.toTrustedDeviceModel()
                    trustedDevice.deviceFingerprint == fingerprintToCheck
                } catch (ex: Exception) {
                    logger.error(">>>> isDeviceTrusted() :: exception message = ${ex.message}, cause = ${ex.cause}")
                    false
                }
            }
    }

    override fun requiresUser(): Boolean = true
    override fun configuredFor(session: KeycloakSession, realm: RealmModel, user: UserModel): Boolean = true
    override fun setRequiredActions(session: KeycloakSession, realm: RealmModel, user: UserModel) {}
    override fun close() {}
}