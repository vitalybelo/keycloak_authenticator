package keycloak.spi.trusted_device.conditional

import keycloak.spi.trusted_device.alternative.TrustedDeviceConfig
import keycloak.spi.trusted_device.clearDeviceCookieAndCredential
import keycloak.spi.trusted_device.cookie
import keycloak.spi.trusted_device.isTrustedDeviceVerified
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel


/**
 * Назначение провайдера состоит в проверке fingerprint доверенного устройства.
 * Основной смысл заключается в том, чтобы освободить пользователя от постоянного ввода второго фактора
 * на доверенном устройстве. Если аутентификатор находит персонализированную cookie, он валидирует jwt токен,
 * извлекает из него fingerprint, сравнивает его с сохраненным в credentials и если они совпадают, тогда ...
 * Если проверка закончилась успешно, возвращаем false, чтобы прервать выполнение потока и не вызывать 2FA.
 * Если fingerprint не валидирован по любому условию, возвращаем true и выполняем поток с прохождением 2FA.
 * @author Belotserkovskii Vitalii (c) 2026
 */
class ConditionalTrustedDeviceAuthenticator : ConditionalAuthenticator {

    companion object {
        private val logger = Logger.getLogger(ConditionalTrustedDeviceAuthenticator::class.java.name)
    }

    /**
     * Основной метод для Condition.
     * Вначале метод проверяет условие isDeleteOn = true, удаляет fingerprint из cookie и credential, return true.
     * Затем, смотрим на выключатель работы аутентификатора, если ему работать не положено, завершаемся return true.
     * Проверяем наличие персонализированное cookie хранящей fingerprint - если cookie нет завершаемся return true.
     * Достав fingerprint, извлекаем сохраненный из credential и сравниваем. При совпадении возвращаем false.
     * Это будет означать, что устройство доверенное, продолжать поток не надо, разрешаем вход пользователю.
     * @return true - если мы хотим запустить subflow 2FA.
     * @return false - если мы хотим пропустить subflow 2FA
     */
    override fun matchCondition(context: AuthenticationFlowContext): Boolean {

        val trustedDeviceConfig = TrustedDeviceConfig.init(context)

        if (trustedDeviceConfig.isDeleteOn) {
            logger.warn(">>>> Delete Trusted Device fingerprint cookie for user = ${context.user?.username} :: 2FA REQUIRED.")
            context.clearDeviceCookieAndCredential()
            return true
        }

        if (!trustedDeviceConfig.isSwitchOn) {
            logger.warn(">>>> Conditional: Trusted Device checker disabled :: 2FA REQUIRED.")
            return true
        }

        val cookie = context.cookie()
        if (cookie == null) {
            logger.warn(">>>> Conditional: No trusted device fingerprint could be found :: 2FA REQUIRED.")
            return true
        }

        return if (context.isTrustedDeviceVerified()) {
            logger.debug(">>>> Conditional success :: device is TRUSTED! Skipping 2FA subflow.")
            false // прерываем выполнение, пропуская 2FA
        } else {
            logger.warn(">>>> Conditional failed :: device is not TRUSTED! :: 2FA REQUIRED.")
            true // продолжаем выполнение, вызывая 2FA
        }
    }

    /**
     * Сюда флоу штатно попадать не должен. Но на случай фантомного сабмита или кнопки "назад"
     */
    override fun action(context: AuthenticationFlowContext) {
        logger.warn(">>>> ConditionalTrustedDeviceAuthenticator received an unexpected action() submit.")
        context.attempted()
    }

    override fun requiresUser(): Boolean = true
    override fun configuredFor(session: KeycloakSession, realm: RealmModel, user: UserModel): Boolean = true
    override fun setRequiredActions(session: KeycloakSession, realm: RealmModel, user: UserModel) {}
    override fun close() {}
}