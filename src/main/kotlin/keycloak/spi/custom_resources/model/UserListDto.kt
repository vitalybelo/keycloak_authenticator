package keycloak.spi.custom_resources.model

data class UserListDto (

    var count: Int = 0,
    var userNames: List<String> =  emptyList()
)