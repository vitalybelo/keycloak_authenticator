package keycloak.spi.brute_force_locker

import keycloak.spi.constants.Constants

/**
 * isSwitchedOn = если true, тогда проверка количества ошибок используется
 * maxFailures = максимальное количество ошибок входа, перед наступлением временной блокировки
 * blockDurationMinutes = время в минутах, на которое выполняется временная блокировка пользователя
 * resetDurationMinutes = время в минутах, после которых сбрасываются ошибки входа не повлекшие блокировку
 *
 * quickLoginCheckInMillis = количество миллисекунд, для определения попытки быстрого входа с ошибкой
 * quickLoginBlockInMinutes = время в минутах для установки временной блокировки после попытки быстрого входа
 * эти два параметра связаны так, если за промежуток времени меньший quickLoginCheckInMillis произойдет два
 * ошибочных ввода пароля, система расценивает это как реальный brute force и блокирует пользователя
 * на quickLoginBlockInMinutes минут
 *
 * criticalFailuresThreshold = значение критического количества ошибок за определенной время
 * criticalTimeWindowMinutes = период времени в течение которого происходит критическое количество ошибок
 * последние два параметра связаны между собой, если в течение времени criticalTimeWindowMinutes произойдет
 * criticalFailuresThreshold количество ошибок
 */
data class BruteForceConfig(

    val isSwitchedOn: Boolean = Constants.BF_CONFIG_SWITCH_VALUE,
    val maxFailures: Int = Constants.BF_CONFIG_MAX_FAILURES_VALUE,
    val blockDurationMinutes: Long = Constants.BF_CONFIG_BLOCK_MINUTES_VALUE,
    val resetDurationMinutes: Long = Constants.BF_CONFIG_RESET_MINUTES_VALUE,
    val quickLoginCheckInMillis: Long = Constants.BF_CONFIG_QUICK_CHECK_VALUE,
    val quickLoginBlockInMinutes: Long = Constants.BF_CONFIG_QUICK_BLOCK_VALUE,

    val criticalFailuresThreshold: Int = Constants.BF_CONFIG_CRITICAL_FAILURES_VALUE,
    val criticalTimeWindowMinutes: Long = Constants.BF_CONFIG_CRITICAL_WINDOW_VALUE
)