package keycloak.spi.conditional_attribute

import keycloak.spi.common.AuthenticationUtils
import org.jboss.logging.Logger
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel


class AttributeConditional(): ConditionalAuthenticator {

    companion object {
        val SINGLETON: AttributeConditional = AttributeConditional()
        private val logger = Logger.getLogger(AttributeConditional::class.java)
        private val authenticationUtils = AuthenticationUtils()
    }


    /**
     * Проверяет наличие у пользователя требуемого атрибута = требуемому значению
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

        authenticationUtils.contextEnabledOrNull(context) ?: return false
        val user = context!!.user ?: return false
        val attributeConfig = AttributeAuthConfig(context)
        if (attributeConfig.isConfigNotPresented()) return false

        val isNative = attributeConfig.isNative!!
        val expectedAttributeName = attributeConfig.attributeName!!
        val expectedAttributeList = attributeConfig.attributeValues!!

        // пробуем найти нужный атрибут и значение в учётной записи пользователя
        user.getFirstAttribute(expectedAttributeName)?.let { foundValue ->

            val message = ">>>> Found user attribute \"$expectedAttributeName\" = [$foundValue]"
            if (expectedAttributeList.contains(foundValue)) {
                logger.info(">>>> $message is matched conditional")
                return !isNative
            } else {
                logger.info(">>>> $message does not match conditional")
            }
        }
        // пробуем найти нужный атрибут в любой из групп, назначенных пользователю
        var attributeValue: String? = null
        if (attributeConfig.isGroups == true) {
            val isFoundInGroups = user.groupsStream.anyMatch {
                groupModel ->
                attributeValue = groupModel.getFirstAttribute(expectedAttributeName)
                attributeValue != null && expectedAttributeList.contains(attributeValue)
            }
            val message = ">>>> Found group attribute \"$expectedAttributeName\" = [$attributeValue]"
            if (isFoundInGroups) {
                logger.info(">>>> $message is matched conditional")
                return !isNative
            } else {
                logger.info(">>>> $message does not match conditional")
            }
        }
        // ничего не нашли
        return isNative
    }


    override fun action(context: AuthenticationFlowContext?) {
    }

    override fun requiresUser(): Boolean {
        return true
    }

    override fun setRequiredActions(
        p0: KeycloakSession?,
        p1: RealmModel?,
        p2: UserModel?
    ) {
    }

    override fun close() {
    }

}