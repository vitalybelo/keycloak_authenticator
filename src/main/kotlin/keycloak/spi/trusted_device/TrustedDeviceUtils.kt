package keycloak.spi.trusted_device

import jakarta.ws.rs.core.Cookie
import jakarta.ws.rs.core.NewCookie
import keycloak.spi.constants.Constants
import keycloak.spi.trusted_device.credentials.TrustedDeviceCredentialModel
import org.jboss.logging.Logger
import org.keycloak.TokenVerifier
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.credential.CredentialModel
import org.keycloak.crypto.Algorithm
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.representations.JsonWebToken
import org.keycloak.crypto.KeyUse
import org.keycloak.crypto.SignatureProvider
import org.keycloak.jose.jws.JWSInput
import org.keycloak.models.UserModel

private val logger = Logger.getLogger("TrustedDeviceUtils")


fun AuthenticationFlowContext.cookie(): Cookie? {
    val personalizedName = this.getCookieName()
    return this.httpRequest.httpHeaders.cookies[personalizedName]
}

/**
 * Возвращает персонализированное название cookie для хранения fingerprint
 */
fun AuthenticationFlowContext.getCookieName(): String {
    val userId = this.user?.id ?: return Constants.ANONYMOUS
    return "${Constants.TRUSTED_DEVICE_COOKIE_NAME}_$userId"
}

fun AuthenticationFlowContext.clearDeviceCookie() {

    val path = this.session.context.uri.baseUri.path
    val personalizedCookieName = this.getCookieName()

    val cookie = NewCookie.Builder(personalizedCookieName)
        .value("")
        .path(path)
        .maxAge(0)
        .secure(this.realm.sslRequired.isRequired(this.connection))
        .httpOnly(true)
        .build()

    this.session.context.httpResponse.setCookieIfAbsent(cookie)
}

/**
 * Удаляет cookie доверенного устройства и связанный с ним credential из БД пользователя.
 * Вначале метод ищет нужную cookie, если в устройстве не сохранен fingerprint - выходим.
 * Далее, извлекаем из cookie зашифрованный jwt токен, извлекаем из него fingerprint.
 * Удаляем fingerprint на устройстве из cookie. Затем ищем соответствующий credential
 * в учётной записи пользователя и удаляем его
 */
fun AuthenticationFlowContext.clearDeviceCookieAndCredential() {


    val cookie = this.cookie() ?: return
    var fingerprint: String?

    // попытаемся достать fingerprint из cookie без строгой верификации подписи
    try {
        val jws = JWSInput(cookie.value)
        val token = jws.readJsonContent(JsonWebToken::class.java)
        fingerprint = token.subject
    } catch (e: Exception) {
        logger.warn(">>>> Extract fingerprint from cookie for deletion failed :: message = ${e.message}, cause = ${e.cause}")
        return
    }

    this.clearDeviceCookie() // удаляем найденную cookie
    // если fingerprint найден, ищем и удаляем соответствующий credential
    val user = this.user
    if (user != null && !fingerprint.isNullOrBlank()) {

        val credentialManager = user.credentialManager()
        credentialManager.getStoredCredentialsByTypeStream(Constants.TRUSTED_DEVICE_CREDENTIAL_TYPE)
            .filter { credential ->
                try {
                    val trustedDevice = credential.toTrustedDeviceModel()
                    trustedDevice.deviceFingerprint == fingerprint
                } catch (ex: Exception) {
                    logger.error(">>>> Converting fingerprint to trustedDevice failed :: ${ex.message}, cause: ${ex.cause}")
                    false
                }
            }
            .forEach { credential ->
                credentialManager.removeStoredCredentialById(credential.id)
                logger.info(">>>> Removed trusted device credential (id: ${credential.id}) for user ${user.username}")
            }
    }
}

/**
 * Проверяет криптографическую подпись токена с использованием активных ключей realm.
 * @return true, если подпись токена валидна.
 */
fun TokenVerifier<JsonWebToken>.verifySignature(
    session: KeycloakSession,
    realm: RealmModel
): Boolean {
    return try {
        val kid = this.header.keyId
        val algorithm = this.header.algorithm?.name ?: Algorithm.RS256
        val keyWrapper =
            session.keys().getKey(realm, kid, KeyUse.SIG, algorithm) ?: return false

        val signatureProvider = session.getProvider(SignatureProvider::class.java, algorithm)
        val verifierContext = signatureProvider.verifier(keyWrapper.kid)

        this.verifierContext(verifierContext).verify()
        true

    } catch (ex: Exception) {
        // вероятнее всего мы словили VerificationException - протух токен или не прошел crypto проверку
        logger.error(">>>> Exception in verification fingerprint: message = ${ex.message}, cause = ${ex.cause}")
        false
    }
}

/**
 * Выполняет проверку идентичности fingerprint извлеченного из cookie и сохраненного в credential.
 * При проверке, если у пользователя не будет найден сохраненный fingerprint или этот fingerprint
 * не совпадает с извлеченным из cookie, метод вернет false, далее нужно обязательно удалить cookie.
 * @param user ресурс управления пользователем
 * @param fingerprintFromCookie отпечаток устройства сохраненный в cookie
 * @return true, если fingerprint устройства и учетной записи совпадают
 */
fun isDeviceTrusted(user: UserModel, fingerprintFromCookie: String): Boolean {
    return user.credentialManager()
        .getStoredCredentialsByTypeStream(Constants.TRUSTED_DEVICE_CREDENTIAL_TYPE)
        .anyMatch { credentialModel ->
            try {
                val trustedDevice = credentialModel.toTrustedDeviceModel()
                trustedDevice.deviceFingerprint == fingerprintFromCookie
            } catch (ex: Exception) {
                logger.error(">>>> isDeviceTrusted() :: exception message = ${ex.message}, cause = ${ex.cause}")
                false
            }
        }
}


/**
 * Проверяет валидность токена в cookie и проверяет, есть ли устройство в базе (credentials).
 * Если проверка провалилась (подпись неверна или креды удалены), вычищает cookie и credentials.
 * @return true - если устройство доверенное и валидное (можно пропустить 2FA).
 */
fun AuthenticationFlowContext.isTrustedDeviceVerified(): Boolean {

    val cookie = this.cookie()
    if (cookie == null) {
        // персонализированная cookie вообще не найдена, устройство не доверенное
        logger.warn(">>>> No trusted device fingerprint could be found.")
        return false
    }

    return try {
        val verifier = TokenVerifier.create(cookie.value, JsonWebToken::class.java)

        if (!verifier.verifySignature(this.session, this.realm)) {
            // персонализированная cookie найдена, но она не прошла верификацию ключами realm, удаляем fingerprints
            logger.warn(">>> Token signature verification failed or key not found. Clearing cookie and credential.")
            this.clearDeviceCookieAndCredential()
            return false
        }

        val deviceFingerprint = verifier.token.subject
        val user = this.user

        // персонализированная cookie найдена, верифицирована, fingerprint извлечен из jwt токена,
        if (user != null && isDeviceTrusted(user, deviceFingerprint)) {
            // credential fingerprint учетной записи пользователя с ней совпадает, устройство доверенное
            logger.debug(">>>> Device is TRUSTED!")
            true
        } else {
            // credential fingerprint учетной записи пользователя с ней не совпадает, удаляем fingerprints
            logger.warn(">>>> Device fingerprint not found in DB (possibly removed). Clearing cookie and credential.")
            this.clearDeviceCookieAndCredential()
            false
        }

    } catch (e: Exception) {
        // как сюда попасть, я лично не знаю, ловушка была задумана до того, как код был разделен на
        // отдельные методы, теперь в этих методах свои ловушки и они не вылетают наружу, посмотрим, вдруг выстрелит
        logger.error(">>>> Verification Exception: message = ${e.message}, cause = ${e.cause}")
        false
    }
}


/**
 * Формирует экземпляр класса TrustedDeviceCredentialModel из стандартной сущности keycloak
 */
fun CredentialModel.toTrustedDeviceModel(): TrustedDeviceCredentialModel {
    val model = TrustedDeviceCredentialModel()
    model.id = this.id
    model.type = this.type
    model.createdDate = this.createdDate
    model.userLabel = this.userLabel
    model.secretData = this.secretData
    model.credentialData = this.credentialData
    return model
}
