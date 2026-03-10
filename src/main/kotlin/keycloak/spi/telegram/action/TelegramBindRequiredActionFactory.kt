package keycloak.spi.telegram.action

import keycloak.spi.constants.Constants
import org.jboss.logging.Logger
import org.keycloak.Config
import org.keycloak.authentication.RequiredActionFactory
import org.keycloak.authentication.RequiredActionProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory


/**
 * Фабрика провайдера привязки двухфакторной аутентификации пользователя через telegram.
 * Отсюда вызывается провайдер для выполнения required action привязки пользователя к telegram
 * @author Belotserkovskii Vitalii (c) 05.03.2026
 */
class TelegramBindRequiredActionFactory : RequiredActionFactory {

    companion object {
        private const val PROVIDER_ID = Constants.TELEGRAM_BIND_ACTION_ID
        private val logger = Logger.getLogger(TelegramBindRequiredActionFactory::class.simpleName)
    }


    override fun create(session: KeycloakSession): RequiredActionProvider {
        return TelegramBindRequiredActionProvider(session)
    }

    override fun init(config: Config.Scope) {
        logger.info(">>>> Initialized >>>>")
    }

    override fun postInit(factory: KeycloakSessionFactory) {
        logger.info(">>>> TelegramBindRequiredActionFactory initialized in WEBHOOK mode >>>>")
    }

    override fun close() {}
    override fun getId(): String = PROVIDER_ID
    override fun getDisplayText(): String = "Bind Telegram 2FA"
}