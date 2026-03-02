package keycloak.spi.brute_force_locker

import keycloak.spi.constants.Constants


data class BruteForceConfig(

    val isSwitchedOn: Boolean = Constants.BF_CONFIG_SWITCH_VALUE,
    val maxFailures: Int = Constants.BF_CONFIG_MAX_FAILURES_VALUE,
    val blockDurationMinutes: Long = Constants.BF_CONFIG_BLOCK_MINUTES_VALUE,
    val resetDurationMinutes: Long = Constants.BF_CONFIG_RESET_MINUTES_VALUE,
    val quickLoginCheckInMillis: Long = Constants.BF_CONFIG_QUICK_CHECK_VALUE,
    val quickLoginBlockInMinutes: Long = Constants.BF_CONFIG_QUICK_BLOCK_VALUE

)