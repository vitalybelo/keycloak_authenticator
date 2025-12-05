package keycloak.spi.event_listener

import org.jboss.logging.Logger
import org.keycloak.events.Event
import org.keycloak.events.EventListenerProvider
import org.keycloak.events.admin.AdminEvent
import org.keycloak.models.KeycloakSession
import org.keycloak.util.JsonSerialization


class CustomEventListenerProvider(

    private val session: KeycloakSession?
): EventListenerProvider {

    companion object {
        private val logger = Logger.getLogger(CustomEventListenerProvider::class.java)
    }


    override fun onEvent(event: Event?) {

        if (event != null) {
            try {
                val jsonString = JsonSerialization.writeValueAsString(event)
                logger.info(">>>> onEvent: ${event.type}")
                logger.info(">>>> Event JSON = $jsonString")
            } catch (e: Exception) {
                logger.error("Exception occurred while handling event ${e.message}, cause = ${e.cause}")
            }
        }
    }


    override fun onEvent(adminEvent: AdminEvent?, p1: Boolean) {

        if (adminEvent != null) {
            val jsonString = JsonSerialization.writeValueAsString(adminEvent)
            logger.info(">>>> onEvent: ${adminEvent.operationType}")
            logger.info(">>>> Event JSON = $jsonString")

            val representation: String? = adminEvent.representation
            if (!representation.isNullOrEmpty()) {
                try {
                    logger.info(">>>> Representation = $representation")
                    /*
                    val user: UserRepresentation? =
                        JsonSerialization.readValue(representation, UserRepresentation::class.java)
                    logger.info(">>>> attributes = ${user?.attributes}")
                    logger.info(">>>> abscust_id = ${user?.attributes["abscustId"]}")
                    */
                } catch (ex: Exception) {
                    logger.error("Exception occurred while handling event :: ${ex.message}, cause = ${ex.cause}")
                }
            }
            logger.info(">>>> Session = ${session?.attributes}")
        }
    }


    override fun close() {
        logger.debug(">>>> Provider closed successfully")
    }

}