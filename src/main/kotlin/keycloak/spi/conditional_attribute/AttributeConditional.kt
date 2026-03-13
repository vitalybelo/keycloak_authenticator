package keycloak.spi.conditional_attribute

import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel


class AttributeConditional: ConditionalAuthenticator {

    companion object {
        private val logger = Logger.getLogger(AttributeConditional::class.java)
    }


    /**
     * Проверяет наличие у пользователя требуемого атрибута и соответствие требуемому значению
     * Вначале из контекста потока извлекаются параметры конфигурации аутентификатора
     * Возвращаемые значения FALSE на этапе проверки:
     * -------------------------------------------------------------------------------
     * 1. если контекст потока по каким то причинам = null
     * 2. если userModel по каким то причинам отсутствует
     * 3. если некорректно задана конфигурация conditional
     *
     * @param context контекст потока аутентификации
     * @return true если условия заданное параметрами конфигурации - удовлетворяется, с учетом
     * присутствия признака негативного выхода - isNegative
     */
    override fun matchCondition(context: AuthenticationFlowContext?): Boolean {

        if (context == null || context.user == null) return false

        val user = context.user
        val attributeConfig = AttributeAuthConfig.init(context)

        if (attributeConfig.isNullOrEmpty()) {
            logger.error(">>>> Authentication config is not presented. >>>>")
            return false
        }
        val isNegate = attributeConfig.isNegate
        val expectedAttributeName = attributeConfig.attributeName
        val expectedAttributeList = attributeConfig.attributeValues

        // пробуем найти нужный атрибут и значение в учётной записи пользователя
        user.getFirstAttribute(expectedAttributeName)?.let { foundValue ->

            if (expectedAttributeList.contains(foundValue)) {
                logger.debug(">>>> Found user attribute \"$expectedAttributeName\" = [$foundValue] is matched conditional")
                return !isNegate
            } else {
                logger.debug(">>>> User attribute \"$expectedAttributeName\" = [$foundValue] does not match conditional = $expectedAttributeList")
            }
        }
        // пробуем найти нужный атрибут в любой из групп, назначенных пользователю
        if (attributeConfig.isGroups) {

            // ищем первую группу у пользователя в которой есть нужный атрибут с нужным значением
            val matchedGroup = user.groupsStream
                .filter { groupModel ->
                    val value = groupModel.getFirstAttribute(expectedAttributeName)
                    value != null && expectedAttributeList.contains(value)
                }
                .findFirst()
                .orElse(null)

            if (matchedGroup != null) {
                // нашли, отображаем сообщение и выходим
                val matchedValue = matchedGroup.getFirstAttribute(expectedAttributeName)
                logger.debug(">>>> Found group attribute \"$expectedAttributeName\" = [$matchedValue] is matched conditional = $expectedAttributeList")
                return !isNegate
            } else {
                logger.debug(">>>> Group attribute \"$expectedAttributeName\" does not match conditional")
            }
        }
        // ничего не нашли
        return isNegate
    }

    override fun action(context: AuthenticationFlowContext?) {}
    override fun requiresUser(): Boolean = true
    override fun setRequiredActions(p0: KeycloakSession?, p1: RealmModel?, p2: UserModel?) {}
    override fun close() {}

}