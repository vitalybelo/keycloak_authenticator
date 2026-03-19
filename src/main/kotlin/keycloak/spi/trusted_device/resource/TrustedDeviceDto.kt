package keycloak.spi.trusted_device.resource

data class TrustedDeviceDto(

    val id: String,
    val deviceName: String,
    val createdAt: Long

)