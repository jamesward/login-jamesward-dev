package com.jamesward

import com.sun.net.httpserver.HttpServer
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import tools.jackson.databind.ObjectMapper
import java.net.InetSocketAddress
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test

class CimdRegisteredClientRepositoryTest {

    private lateinit var server: HttpServer
    private val docs = mutableMapOf<String, String>()
    private var requestCount = 0

    private val objectMapper = ObjectMapper()

    @BeforeTest
    fun startServer() {
        docs.clear()
        requestCount = 0
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/") { exchange ->
            requestCount++
            val body = docs[exchange.requestURI.path]?.toByteArray()
            if (body == null) {
                exchange.sendResponseHeaders(404, -1)
            } else {
                exchange.responseHeaders.add("Content-Type", "application/json")
                exchange.sendResponseHeaders(200, body.size.toLong())
                exchange.responseBody.use { it.write(body) }
            }
            exchange.close()
        }
        server.start()
    }

    @AfterTest
    fun stopServer() {
        server.stop(0)
    }

    private fun clientIdUrl(path: String) = "http://127.0.0.1:${server.address.port}$path"

    private fun serveDoc(path: String, document: Map<String, Any>): String {
        val clientId = clientIdUrl(path)
        docs[path] = objectMapper.writeValueAsString(mapOf("client_id" to clientId) + document)
        return clientId
    }

    private val staticClient: RegisteredClient = RegisteredClient.withId("static")
        .clientId("static")
        .clientSecret("{noop}static")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("http://127.0.0.1:8081/callback")
        .build()

    private fun repository(allowLoopback: Boolean = true) = CimdRegisteredClientRepository(
        InMemoryRegisteredClientRepository(staticClient),
        TokenSettings.builder().build(),
        allowLoopback
    )

    @Test
    fun `resolves a client from a metadata document`() {
        val clientId = serveDoc(
            "/client.json", mapOf(
                "client_name" to "Test MCP Client",
                "redirect_uris" to listOf("http://127.0.0.1:8081/callback"),
                "grant_types" to listOf("authorization_code", "refresh_token"),
                "token_endpoint_auth_method" to "none",
                "scope" to "profile email",
            )
        )

        val registeredClient = repository().findByClientId(clientId)

        assert(registeredClient != null)
        assert(registeredClient!!.clientId == clientId)
        assert(registeredClient.id == clientId)
        assert(registeredClient.clientName == "Test MCP Client")
        assert(registeredClient.clientAuthenticationMethods == setOf(ClientAuthenticationMethod.NONE))
        assert(registeredClient.authorizationGrantTypes == setOf(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN))
        assert(registeredClient.redirectUris == setOf("http://127.0.0.1:8081/callback"))
        assert(registeredClient.scopes == setOf("profile", "email"))
        assert(registeredClient.clientSettings.isRequireProofKey)
    }

    @Test
    fun `resolves the same client by id for token requests`() {
        val clientId = serveDoc("/client.json", mapOf("redirect_uris" to listOf("http://127.0.0.1:8081/callback")))

        assert(repository().findById(clientId)?.clientId == clientId)
    }

    @Test
    fun `still finds clients from the delegate`() {
        assert(repository().findByClientId("static") != null)
        assert(repository().findById("static") != null)
    }

    @Test
    fun `caches resolved clients`() {
        val clientId = serveDoc("/client.json", mapOf("redirect_uris" to listOf("http://127.0.0.1:8081/callback")))
        val repository = repository()

        repository.findByClientId(clientId)
        repository.findByClientId(clientId)

        assert(requestCount == 1)
    }

    @Test
    fun `rejects a document whose client_id does not match its url`() {
        docs["/client.json"] = objectMapper.writeValueAsString(
            mapOf(
                "client_id" to "https://evil.example.com/client.json",
                "redirect_uris" to listOf("http://127.0.0.1:8081/callback"),
            )
        )

        assert(repository().findByClientId(clientIdUrl("/client.json")) == null)
    }

    @Test
    fun `rejects secret-based clients`() {
        val withSecret = serveDoc(
            "/with-secret.json", mapOf(
                "client_secret" to "shhh",
                "redirect_uris" to listOf("http://127.0.0.1:8081/callback"),
            )
        )
        val secretBasic = serveDoc(
            "/secret-basic.json", mapOf(
                "token_endpoint_auth_method" to "client_secret_basic",
                "redirect_uris" to listOf("http://127.0.0.1:8081/callback"),
            )
        )

        assert(repository().findByClientId(withSecret) == null)
        assert(repository().findByClientId(secretBasic) == null)
    }

    @Test
    fun `rejects a document without redirect_uris`() {
        val clientId = serveDoc("/client.json", mapOf("client_name" to "No Redirects"))

        assert(repository().findByClientId(clientId) == null)
    }

    @Test
    fun `ignores client ids that are not urls`() {
        assert(repository().findByClientId("not-a-registered-client") == null)
    }

    @Test
    fun `rejects invalid client id urls`() {
        val repository = repository()
        val base = clientIdUrl("/client.json")
        serveDoc("/client.json", mapOf("redirect_uris" to listOf("http://127.0.0.1:8081/callback")))

        assert(repository.findByClientId("$base#fragment") == null)
        assert(repository.findByClientId(clientIdUrl("")) == null)
        assert(repository.findByClientId(clientIdUrl("/")) == null)
        assert(repository.findByClientId(clientIdUrl("/../client.json")) == null)
    }

    @Test
    fun `rejects http and loopback urls when loopback is not allowed`() {
        val clientId = serveDoc("/client.json", mapOf("redirect_uris" to listOf("http://127.0.0.1:8081/callback")))

        assert(repository(allowLoopback = false).findByClientId(clientId) == null)
    }
}
