package keycloak.spi.event_listener

import keycloak.spi.brute_force_locker.BlockType
import keycloak.spi.brute_force_locker.BruteForceConfig
import keycloak.spi.constants.Constants
import keycloak.spi.utils.getCacheKey
import keycloak.spi.utils.getInfinispanLoginAttemptCache
import keycloak.spi.jackson_mapper.toJsonString
import org.jboss.logging.Logger
import org.keycloak.events.Event
import org.keycloak.events.EventListenerProvider
import org.keycloak.events.EventType
import org.keycloak.events.admin.AdminEvent
import org.keycloak.models.KeycloakSession
import java.util.concurrent.TimeUnit


class CustomEventListenerProvider(
    private val session: KeycloakSession
): EventListenerProvider {

    companion object {
        private val logger = Logger.getLogger(CustomEventListenerProvider::class.java)
    }


    /**
     * Регистрация пользовательских событий
     */
    override fun onEvent(event: Event?) {

        val realmName: String = session.context?.realm?.name ?: "upstream"
        if (event != null) {

            bruteForceDetector(event)
            logger.info(">>>> onEvent: ${event.type} in realm: $realmName")
            logger.info(">>>> Event JSON = ${event.toJsonString()}\n")
        }
    }


    /**
     * Регистрация событий администрирования
     * @param adminEvent админ событие
     * @param includeRepresentation флаг наличия representation
     */
    override fun onEvent(
        adminEvent: AdminEvent?,
        includeRepresentation: Boolean
    ) {

        if (adminEvent != null) {
            logger.info(">>>> onAdminEvent: ${adminEvent.operationType}")
            logger.info(">>>> Event JSON = ${adminEvent.toJsonString()}\n")

            val representation: String? = adminEvent.representation
            if (includeRepresentation) {
                try {
                    logger.info(">>>> Representation = ${representation?.toJsonString()}\n")

                } catch (ex: Exception) {
                    logger.error("Exception occurred while handling event :: ${ex.message}, cause = ${ex.cause}")
                }
            }
        }
    }

    override fun close() {
    }


    /**
     * Выполняет регистрацию событий неправильного ввода логина или пароля (улучшенный brute force)
     * @param event пользовательское событие
     */
    private fun bruteForceDetector(event: Event) {

        if (event.type != EventType.LOGIN_ERROR) return
        val userId = event.userId ?: return
        val realmId = event.realmId ?: return

        val config = bruteForceConfiguration()
        if (!config.isSwitchedOn) return

        val cacheKey = getCacheKey(realmId, userId)
        val cache = getInfinispanLoginAttemptCache(session)

        val attempt = cache.compute(cacheKey) { _, currentAttempt ->

            val currentMillis = System.currentTimeMillis()
            val previousBlockType = currentAttempt?.blockType ?: BlockType.NONE // Запоминаем прошлый статус

            val newFailures = (currentAttempt?.failures ?: emptyList()).takeLast(50).toMutableList()
            newFailures.add(currentMillis)

            val validWindowInMillis = TimeUnit.MINUTES.toMillis(config.criticalTimeWindowMinutes)
            val lastValidFailureInMillis = currentMillis - validWindowInMillis
            val filteredCount = newFailures.count { it > lastValidFailureInMillis }
            val failuresCount = newFailures.size

            var blockInMinutes: Long
            var blockType: BlockType
            when {
                // если уже был CRITICAL или только что достигли порога
                previousBlockType == BlockType.CRITICAL || filteredCount >= config.criticalFailuresThreshold -> {
                    blockType = BlockType.CRITICAL
                    blockInMinutes = config.criticalBlockInMinutes
                    logger.debug(">>>> CRITICAL failures: $filteredCount")
                }
                // если уже был TEMPORARY или только что достигли лимита
                previousBlockType == BlockType.TEMPORARY || failuresCount >= config.maxFailures -> {
                    blockType = BlockType.TEMPORARY
                    blockInMinutes = config.blockDurationMinutes
                    logger.debug(">>>> TEMPORARY failures: $failuresCount")
                }
                // проверка на "быстрый вход"
                newFailures.size > 1 && (newFailures.last() - newFailures[newFailures.size - 2] <= config.quickLoginCheckInMillis) -> {
                    blockType = BlockType.TEMPORARY
                    blockInMinutes = config.blockDurationMinutes
                    logger.debug(">>>> QUICK LOGIN failures with total: $failuresCount")
                }

                else -> {
                    blockType = BlockType.NONE
                    blockInMinutes = 0L
                }
            }

            logger.debug(""">>>>
                | Login error compilation
                | -------------------------------------
                | total failures: $failuresCount
                | block type: $blockType
                | block time: $blockInMinutes minutes
                | is blocked: ${blockType.isBlocked()}
                | -------------------------------------
            """.trimIndent()
            )

            LoginAttempt(
                failures = newFailures,
                blockType = blockType,
                blockInMinutes = blockInMinutes
            )
        }

        // Устанавливаем блокировку в зависимости от статуса blockType
        if (attempt != null) {
            if (attempt.blockType.isBlocked()) {
                logger.debug(""">>>>
                    | ---------------------------------------------------------------------------------------------
                    | ATTENTION !!!
                    |
                    | Блокировка на ${attempt.blockInMinutes} минут, после ${attempt.failures.size} попыток:
                    | Пользователь = ${event.userId}
                    | ---------------------------------------------------------------------------------------------
                    """.trimIndent()
                )
                // ставим время жизни записи, равное времени блокировки
                cache.put(cacheKey, attempt, attempt.blockInMinutes, TimeUnit.MINUTES)
            } else {
                logger.info(""">>>>
                    | ---------------------------------------------------------------------------------------------
                    | Ошибка входа, сброс ошибок через ${config.resetDurationMinutes} минут:
                    | Пользователь = ${event.userId}
                    | Попытка = ${attempt.failures}
                    | ---------------------------------------------------------------------------------------------
                    """.trimIndent()
                )
                // окно накопления ошибок, если блокировки еще нет, но счетчик уже есть
                cache.put(cacheKey, attempt, config.resetDurationMinutes, TimeUnit.MINUTES)
            }
        }
    }


    /**
     * Ищет среди зарегистрированных аутентификаторов рабочей области, кастомный BRUTE_FORCE_PASSWORD_FORM_ID.
     * Если находит, читает его настройки, инициализирует экземпляр класса BruteForceConfig и завершает работу.
     * Если не находит, успокаивается дефолтными настройки hardcoded и закрывает на меня глаза
     * @return экземпляр класса BruteForceConfig кастомных настроек
     * @author Belotserkovskii Vitaly (c) 27.02.2026
     */
    fun bruteForceConfiguration(): BruteForceConfig {

        val realm = session.context?.realm ?: return BruteForceConfig()

        // ищем настроенный шаг (execution) в любом Flow, который использует наш аутентификатор
        val execution = realm.authenticationFlowsStream
            .flatMap { flow -> realm.getAuthenticationExecutionsStream(flow.id) }
            .filter { it.authenticator == Constants.BRUTE_FORCE_PASSWORD_FORM_ID }
            .findFirst()
            .orElse(null)

        if (execution == null || execution.authenticatorConfig == null) {
            logger.warn("Brute force authenticator is not configured in this realm.")
            return BruteForceConfig()
        }

        val configModel = realm.getAuthenticatorConfigById(execution.authenticatorConfig)
        if (configModel == null) {
            logger.warn("Configuration model for brute force not found.")
            return BruteForceConfig()
        }

        val configMap = configModel.config
        val isSwitchedOn = configMap[Constants.BF_CONFIG_SWITCH_KEY]?.toBoolean() ?: Constants.BF_CONFIG_SWITCH_VALUE
        val maxFailures = configMap[Constants.BF_CONFIG_MAX_FAILURES_KEY]?.toInt() ?: Constants.BF_CONFIG_MAX_FAILURES_VALUE
        val blockMinutes = configMap[Constants.BF_CONFIG_BLOCK_MINUTES_KEY]?.toLong() ?: Constants.BF_CONFIG_BLOCK_MINUTES_VALUE
        val resetMinutes = configMap[Constants.BF_CONFIG_RESET_MINUTES_KEY]?.toLong() ?: Constants.BF_CONFIG_RESET_MINUTES_VALUE
        val quickLoginMillis = configMap[Constants.BF_CONFIG_QUICK_CHECK_KEY]?.toLong() ?: Constants.BF_CONFIG_QUICK_CHECK_VALUE
        val criticalFailures = configMap[Constants.BF_CONFIG_CRITICAL_FAILURES_KEY]?.toInt() ?: Constants.BF_CONFIG_CRITICAL_FAILURES_VALUE
        val criticalWindowInMinutes = configMap[Constants.BF_CONFIG_CRITICAL_WINDOW_KEY]?.toLong() ?: Constants.BF_CONFIG_CRITICAL_WINDOW_VALUE
        val criticalBlockInMinutes = configMap[Constants.BF_CONFIG_CRITICAL_BLOCK_KEY]?.toLong() ?: Constants.BF_CONFIG_CRITICAL_BLOCK_VALUE

        logger.debug(""">>>>
            | Brute force configuration found
            | --------------------------------------------------
            | isSwitchedOn = $isSwitchedOn
            | maxFailures = $maxFailures
            | blockDurationMinutes = $blockMinutes
            | resetDurationMinutes = $resetMinutes
            | quickLoginMillis = $quickLoginMillis
            | criticalFailures = $criticalFailures
            | criticalWindowMinutes = $criticalWindowInMinutes
            | criticalBlockMinutes = $criticalBlockInMinutes
        """.trimIndent()
        )

        return BruteForceConfig(
            isSwitchedOn = isSwitchedOn,
            maxFailures = maxFailures,
            blockDurationMinutes = blockMinutes,
            resetDurationMinutes = resetMinutes,
            quickLoginCheckInMillis = quickLoginMillis,
            criticalFailuresThreshold = criticalFailures,
            criticalTimeWindowMinutes = criticalWindowInMinutes,
            criticalBlockInMinutes = criticalBlockInMinutes
        )
    }

}