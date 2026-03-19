package keycloak.spi.trusted_device.alternative

import keycloak.spi.trusted_device.clearDeviceCookieAndCredential
import keycloak.spi.trusted_device.isTrustedDeviceVerified
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.Authenticator
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel

/**
 * Назначение провайдера состоит в проверке fingerprint доверенного устройства.
 * Основной смысл заключается в том, чтобы освободить пользователя от постоянного ввода второго фактора
 * на доверенном устройстве. Если аутентификатор находит персонализированную cookie, он валидирует jwt токен,
 * извлекает из него fingerprint, сравнивает его с сохраненным в credentials и если они совпадают, тогда ...
 * Если проверка закончилась успешно, возвращаем success, чтобы прервать выполнение потока и не вызывать 2FA.
 * Если fingerprint не валидирован по любому условию, возвращаем attempted и выполняем поток с прохождением 2FA.
 * Подразумевается что аутентификатор будет установлен в альтернативном саб-флоу, тогда это сработает.
 * @author Belotserkovskii Vitalii (c) 2026
 */
class TrustedDeviceAuthenticator : Authenticator {

    companion object {
        private val logger = Logger.getLogger(TrustedDeviceAuthenticator::class.java.name)
    }

    /**
     * Вначале метод проверяет условие isDeleteOn = true, удаляет fingerprint отовсюду и завершаемся attempted.
     * Затем, смотрим на выключатель работы аутентификатора, если ему работать не положено, завершаемся attempted.
     * Проверяем наличие персонализированное cookie хранящей jwt токен с отпечатком, если токен найден, верифицируем
     * извлеченный токен ключами realm, если верификация успешная, извлекаем из него fingerprint нашего устройства.
     * Сравниваем этот fingerprint с хранящимся в credential учетной записи пользователя таким же fingerprint.
     * Если они совпадают, аутентификатор вернет success, и в ряду стоящих с ним alternative завершит поток.
     */
    override fun authenticate(context: AuthenticationFlowContext) {

        val trustedDeviceConfig = TrustedDeviceConfig.init(context)

        if (trustedDeviceConfig.isDeleteOn) {
            logger.warn(">>>> Delete Trusted Device fingerprint cookie for user = ${context.user?.username} :: 2FA REQUIRED")
            context.clearDeviceCookieAndCredential()
            context.attempted()
            return
        }

        if (!trustedDeviceConfig.isSwitchOn) {
            logger.warn(">>>> Trusted Device Authenticator disabled :: 2FA REQUIRED")
            context.attempted()
            return
        }

        if (context.isTrustedDeviceVerified()) {
            context.success()
        } else {
            context.attempted()
        }
    }

    /**
     * В Keycloak метод action() никогда не должен оставаться без ответа (bug)
     * Если по какой-то причине (например, кнопка "Назад" в браузере) сюда прилетит POST-запрос.
     * Если метод action() пустой, статус остается null. Keycloak видит null и моментально бросает
     * внутреннюю ошибку сервера — AuthenticationFlowException("Authenticator did not set flow status")
     * Так что здесь, просто передаем управление следующему шагу Alternative. Учтём на будущее.
     * @return всегда attempted
     */
    override fun action(context: AuthenticationFlowContext) {
        logger.warn(">>>> TrustedDeviceAuthenticator received an unexpected action submit. Skipping to next.")
        context.attempted()
    }


    override fun requiresUser(): Boolean = true
    override fun configuredFor(session: KeycloakSession, realm: RealmModel, user: UserModel): Boolean = true
    override fun setRequiredActions(session: KeycloakSession, realm: RealmModel, user: UserModel) {}
    override fun close() {}
}