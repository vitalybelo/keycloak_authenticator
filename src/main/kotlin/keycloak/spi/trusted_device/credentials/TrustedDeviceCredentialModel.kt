package keycloak.spi.trusted_device.credentials

import keycloak.spi.constants.Constants
import org.keycloak.credential.CredentialModel
import org.keycloak.util.JsonSerialization


class TrustedDeviceCredentialModel : CredentialModel() {

    companion object {
        const val TYPE = "trusted-device"

        /**
         * Фабричный метод для создания новой записи в таблице credential
         * @param deviceFingerprint уникальный ключ доверенного устройства
         * @param deviceName имя устройства, которое увидит пользователь в ЛК (например, "Chrome on Mac")
         * @return экземпляр класса TrustedDeviceCredentialModel для сохранения в credentials
         */
        fun create(
            deviceFingerprint: String,
            deviceName: String

        ): TrustedDeviceCredentialModel {

            val model = TrustedDeviceCredentialModel()
            model.type = TYPE
            model.createdDate = System.currentTimeMillis()
            model.userLabel = deviceName

            // упаковываем fingerprint в секретные данные
            val secretMap = mapOf(Constants.TRUSTED_DEVICE_FINGERPRINT to deviceFingerprint)
            model.secretData = JsonSerialization.writeValueAsString(secretMap)

            // здесь можно хранить дополнительные метаданные если нужно (ОС, IP, браузер)
            model.credentialData = "{}"

            return model
        }
   }


    /**
     * Удобный getter для извлечения fingerprint из JSON
     */
    val deviceFingerprint: String
        get() {
            val node = JsonSerialization.mapper.readTree(secretData)
            return node.get(Constants.TRUSTED_DEVICE_FINGERPRINT).asText()
        }
}