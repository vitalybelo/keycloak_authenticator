package keycloak.spi.brute_force_locker

enum class BlockType {

    NONE,
    TEMPORARY,
    CRITICAL;

    fun isBlocked(): Boolean = (this == CRITICAL || this == TEMPORARY)
}