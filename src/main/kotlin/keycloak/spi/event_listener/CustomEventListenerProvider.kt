package keycloak.spi.event_listener

import keycloak.spi.jackson_mapper.toJsonString
import org.jboss.logging.Logger
import org.keycloak.events.Event
import org.keycloak.events.EventListenerProvider
import org.keycloak.events.admin.AdminEvent
import org.keycloak.models.KeycloakSession


class CustomEventListenerProvider(

    private val session: KeycloakSession?
): EventListenerProvider {



    companion object {
        private val logger = Logger.getLogger(CustomEventListenerProvider::class.java)
    }


    override fun onEvent(event: Event?) {

        val realmName: String = session?.context?.realm?.name ?: "upstream"
        if (event != null) {
            try {
                logger.info(">>>> onEvent: ${event.type} in realm: $realmName")
                logger.info(">>>> Event JSON = ${event.toJsonString()}\n")

            } catch (e: Exception) {
                logger.error("Exception occurred while handling event ${e.message}, cause = ${e.cause}")
            }
        }
    }


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
        logger.debug(">>>> CLOSED >>>>>")
    }

}