package keycloak.spi.custom_resources.admin.model

data class UserListDto (

    var count: Int = 0,
    var userNames: List<String> =  emptyList()
)