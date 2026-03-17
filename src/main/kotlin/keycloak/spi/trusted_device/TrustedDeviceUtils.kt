package keycloak.spi.trusted_device

import jakarta.ws.rs.core.Cookie
import keycloak.spi.constants.Constants
import org.jboss.logging.Logger
import org.keycloak.TokenVerifier
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.crypto.Algorithm
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.representations.JsonWebToken
import org.keycloak.crypto.KeyUse
import org.keycloak.crypto.SignatureProvider

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

    val expiredCookie = jakarta.ws.rs.core.NewCookie.Builder(personalizedCookieName)
        .value("")
        .path(path)
        .maxAge(0)
        .secure(this.realm.sslRequired.isRequired(this.connection))
        .httpOnly(true)
        .build()

    this.session.context.httpResponse.setCookieIfAbsent(expiredCookie)
}

/**
 * Проверяет криптографическую подпись токена с использованием активных ключей realm.
 * Возвращает true, если подпись валидна и ключ найден.
 */
fun TokenVerifier<JsonWebToken>.verifySignature(session: KeycloakSession, realm: RealmModel): Boolean {

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

        logger.error(">>>> Exception in verification fingerprint: message = ${ex.message}, cause = ${ex.cause}")
        false
    }
}