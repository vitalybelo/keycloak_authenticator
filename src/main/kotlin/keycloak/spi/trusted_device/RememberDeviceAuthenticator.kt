package keycloak.spi.trusted_device

import jakarta.ws.rs.core.NewCookie
import keycloak.spi.trusted_device.TrustedDeviceCredentialModel.Companion.toTrustedDeviceModel
import org.jboss.logging.Logger
import org.keycloak.TokenVerifier
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.Authenticator
import org.keycloak.crypto.Algorithm
import org.keycloak.crypto.KeyUse
import org.keycloak.crypto.SignatureProvider
import org.keycloak.crypto.SignatureSignerContext
import org.keycloak.jose.jws.JWSBuilder
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.representations.JsonWebToken
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Аутентификатор доверенных устройств пользователя.
 * Работает с cookie клиентского устройства, при первом проходе создается fingerprint для устройства.
 * Данный fingerprint сохраняется в credential пользователя, далее создается crypto подписанный jwt токен,
 * который сохраняется в cookie доверенного устройства.
 * @author Belotserkovskii Vitali, 16.03.2026
 */
class RememberDeviceAuthenticator(
    private val session: KeycloakSession
) : Authenticator {

    companion object {
        const val ONE_SECOND = 1000
        const val CHECKBOX_NAME = "rememberDevice"
        private val logger = Logger.getLogger(RememberDeviceAuthenticator::class.java)
    }


    /**
     * Вначале метода мы проверяем включено ли сохранение доверенных устройств для пользователей.
     * В приближенном варианте, мы проверяем наличие ранее сохраненных cookie, чтобы понять необходимость
     * добавлять credentials пользователю. В более конкретной логике, если мы находим сохраненные cookie,
     * сначала мы проверяем их crypto подпись и если она соответствует - аутентификатор завершает работу.
     * Если cookie отсутствуют или не подтверждена крипто подпись - пользователю выводится экран согласия,
     * на котором нужно установить галочку согласия считать устройство доверенным. После этого формируется
     * fingerprint, который записывается как credential пользователю, для записи в cookie формируется jwt
     */
    override fun authenticate(context: AuthenticationFlowContext) {

        val rememberConfig = RememberDeviceConfig.init(context)
        if (rememberConfig.isSwitchOn.not()) {
            logger.debug(">>>> Remembering device authenticate() disabled by configuration")
            context.success()
            return
        } else {
            logger.debug(">>>> Remembering device authenticate() started")
        }
        // Проверяем cookie и при необходимости восстанавливаем удаленные креды
        if (isCookieProceedSuccessfully(context, rememberConfig)) {
            logger.debug(">>>> Trusted device cookie is valid. Skipping form.")
            context.success()
            return
        }
        val form = context.form().createForm("remember-device.ftl")
        context.challenge(form)
    }


    /**
     * Сюда мы попадаем только если для пользователя не созданы credential и cookie доверенного устройства.
     * Вначале мы
     */
    override fun action(context: AuthenticationFlowContext) {

        // проверяем глобальный switch аутентификатора
        val rememberConfig = RememberDeviceConfig.init(context)
        if (rememberConfig.isSwitchOn.not()) {
            logger.debug(">>>> Remembering device action() disabled by configuration")
            context.success()
            return
        } else {
            logger.debug(">>>> Remembering device action() started")
        }
        // еще раз проверяем, все что проверяли ранее - это важно и обеспечит нам отказоустойчивость
        if (isCookieProceedSuccessfully(context, rememberConfig)) {
            logger.debug(">>>> Trusted device cookie is valid during action. Skipping save.")
            context.success()
            return
        }

        val formData = context.httpRequest.decodedFormParameters
        val isRememberDeviceAgreed = formData.getFirst(CHECKBOX_NAME) == "on"

        if (isRememberDeviceAgreed) {

            val credentialManager = context.user.credentialManager()
            val deviceName = parseDeviceName(context)

            val existingDevice = credentialManager
                .getStoredCredentialsByTypeStream(TrustedDeviceCredentialModel.TYPE)
                .filter { it.userLabel == deviceName }
                .findFirst()
                .orElse(null)

            val fingerprint: String
            if (existingDevice == null) {

                fingerprint = UUID.randomUUID().toString()
                val credentialModel = TrustedDeviceCredentialModel.create(fingerprint, deviceName)
                credentialManager.createStoredCredential(credentialModel)
                logger.debug(">>>> Created new trusted device: $deviceName")
            } else {

                val trustedDevice = existingDevice.toTrustedDeviceModel()
                fingerprint = trustedDevice.deviceFingerprint
                logger.debug(">>>> Device already remembered. Reusing fingerprint for: $deviceName")
            }

            val signedToken = createSignedToken(context.realm, fingerprint, rememberConfig)
            setCookie(context, signedToken, rememberConfig)
        }

        context.success()
    }


    /**
     * Отдельный метод: проверяет подпись cookie и восстанавливает запись в БД, если пользователь её удалил.
     * Вначале метод проверяет наличие сохранённых cookie для пользователя, если находит, идет дальше
     * Далее, проверяется достоверность крипто-графической подписи найденной cookie, ключом keycloak.
     * Если подпись верифицирована, далее мы проверяем наличие соответствующего credential у пользователя.
     * При отсутствии credential - выполняется восстановление на извлеченный из cookie идентификатор
     * Дополнение: восстановление
     * @return true, если cookie существует и валидна
     */
    private fun isCookieProceedSuccessfully(
        context: AuthenticationFlowContext,
        rememberConfig: RememberDeviceConfig
    ): Boolean {

        val cookie = context.cookie() ?: return false
        try {
            // проверяем криптографическую подпись и срок действия токена в cookie
            val verifier =
                TokenVerifier.create(cookie.value, JsonWebToken::class.java)

            if (!verifier.verifySignature(session, context.realm)) {
                logger.warn(">>>> Cookie signature verification failed")
                return false
            }

            // если подпись верна, извлекаем fingerprint
            val fingerprint = verifier.token.subject
            val user = context.user
            val credentialManager = user.credentialManager()

            // проверяем, есть ли у пользователя credentials именно с этим fingerprint, извлеченным из cookie
            val isCredentialFound = credentialManager
                .getStoredCredentialsByTypeStream(TrustedDeviceCredentialModel.TYPE)
                .anyMatch { model ->
                    try {
                        model.toTrustedDeviceModel().deviceFingerprint == fingerprint
                    } catch (ex: Exception) {
                        logger.error(">>>> verifyCookieAndRestoreCredential() message = ${ex.message}, cause = ${ex.cause}")
                        false
                    }
                }

            // у нас коллизия, cookie у нас валидна, но у пользователя нет credential для этого trusted device
            // возможный сценарий: cookie была добавлена ранее, но из учетных данных пользователя, пароль удалили
            // восстанавливаем креды (в дальнейшем здесь нужна логика - удалять куки или восстанавливать креды)
            if (!isCredentialFound) {
                if (rememberConfig.isRecoveryCredential) {

                    val deviceName = parseDeviceName(context)
                    val credentialModel = TrustedDeviceCredentialModel.create(fingerprint, deviceName)
                    credentialManager.createStoredCredential(credentialModel)
                    logger.info(">>>> Restored deleted trusted device credential from valid cookie for user: ${user.username}")

                    // ОБЯЗАТЕЛЬНО обновляем (перевыпускаем) cookie в HTTP ответе!
                    val signedToken = createSignedToken(context.realm, fingerprint, rememberConfig)
                    setCookie(context, signedToken, rememberConfig)
                    return true

                } else {
                    logger.warn(">>>> Credential not found and recovery is disabled. Clearing device cookie.")
                    context.clearDeviceCookie() // Грохаем куку навсегда
                    return false // Возвращаем false, чтобы показать форму заново
                }
            }
            return true

        } catch (e: Exception) {
            // Ошибка проверки подписи или токен протух или непонятно что - выведем сообщение, может узнаем
            logger.warn(">>>> Failed to verify cookie during credential restoration: ${e.message}, cause: ${e.cause}")
            return false
        }
    }


    /**
     * Выполняется создание подписанного крипто-графическим ключом keycloak токена, внутри которого мы сохраним
     * идентификатор доверенного устройства - fingerprint, обезопасив его от прочтения и дальнейшего использования
     * По умолчанию, fingerprint шифруется алгоритмом RS256, дефолтный алгоритм Keycloak
     * @param realm ресурс управления рабочей областью сервисов
     * @param fingerprint уникальный идентификатор устройства
     * @param rememberConfig конфигурация аутентификатора
     * @return подписанный токен для сохранения в cookie
     */
    private fun createSignedToken(
        realm: RealmModel,
        fingerprint: String,
        rememberConfig: RememberDeviceConfig
    ): String {

        val ttlInDays = rememberConfig.cookieTtlDays
        val currentTime = System.currentTimeMillis() / ONE_SECOND
        val expiredTime = currentTime + TimeUnit.DAYS.toSeconds(ttlInDays)
        val tokenPayload = JsonWebToken()
            .id(UUID.randomUUID().toString())
            .subject(fingerprint)
            .iat(currentTime)
            .exp(expiredTime)

        val activeKey = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256)
        val signatureProvider = session.getProvider(SignatureProvider::class.java, Algorithm.RS256)
        val signatureContext: SignatureSignerContext = signatureProvider.signer()

        return JWSBuilder()
            .type("JWT")
            .kid(activeKey.kid)
            .jsonContent(tokenPayload)
            .sign(signatureContext)
    }


    /**
     * Выполняет сохранение подписанного токена доверенного устройства в cookie устройства
     * @param context контекст аутентификации
     * @param token подписанный токен доверенного устройства
     */
    private fun setCookie(
        context: AuthenticationFlowContext,
        token: String,
        config: RememberDeviceConfig
    ) {
        val realm = context.realm
        val path = context.session.context.uri.baseUri.path
        val maxAgeInSeconds = TimeUnit.DAYS.toSeconds(config.cookieTtlDays).toInt()
        val personalizedCookieName = context.getCookieName()

        val cookie = NewCookie.Builder(personalizedCookieName)
            .value(token)
            .path(path)
            .maxAge(maxAgeInSeconds)
            .secure(realm.sslRequired.isRequired(context.connection))
            .httpOnly(true)
            .build()

        context.session.context.httpResponse.setCookieIfAbsent(cookie)
    }


    private fun parseDeviceName(context: AuthenticationFlowContext): String {
        val userAgent = context.httpRequest.httpHeaders.getHeaderString("User-Agent") ?: "Unknown Device"
        return if (userAgent.length > 70) userAgent.substring(0, 70) + "..." else userAgent
    }

    override fun requiresUser(): Boolean = true
    override fun configuredFor(session: KeycloakSession, realm: RealmModel, user: UserModel): Boolean = true
    override fun setRequiredActions(session: KeycloakSession, realm: RealmModel, user: UserModel) {}
    override fun close() {}

}