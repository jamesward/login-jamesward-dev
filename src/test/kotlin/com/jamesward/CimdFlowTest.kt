package com.jamesward

import com.sun.net.httpserver.HttpServer
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.util.UriComponentsBuilder
import tools.jackson.databind.ObjectMapper
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.util.*
import kotlin.test.Test

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = ["cimd.allow-loopback=true"])
class CimdFlowTest(@Autowired val mockMvc: MockMvc) {

    companion object {
        private lateinit var server: HttpServer

        private const val REDIRECT_URI = "http://127.0.0.1:8081/callback"

        private val clientId: String
            get() = "http://127.0.0.1:${server.address.port}/client.json"

        @JvmStatic
        @BeforeAll
        fun startServer() {
            server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
            server.createContext("/client.json") { exchange ->
                val body = ObjectMapper().writeValueAsString(
                    mapOf(
                        "client_id" to clientId,
                        "client_name" to "Test MCP Client",
                        "redirect_uris" to listOf(REDIRECT_URI),
                        "grant_types" to listOf("authorization_code"),
                        "token_endpoint_auth_method" to "none",
                    )
                ).toByteArray()
                exchange.responseHeaders.add("Content-Type", "application/json")
                exchange.sendResponseHeaders(200, body.size.toLong())
                exchange.responseBody.use { it.write(body) }
                exchange.close()
            }
            server.start()
        }

        @JvmStatic
        @AfterAll
        fun stopServer() {
            server.stop(0)
        }
    }

    @Test
    fun `authorization server metadata advertises cimd support`() {
        mockMvc.perform(get("/.well-known/oauth-authorization-server"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.client_id_metadata_document_supported").value(true))
    }

    @Test
    fun `authorization code flow works with a url client id`() {
        val codeVerifier = "test-code-verifier-test-code-verifier-test-1"
        val codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(codeVerifier.toByteArray(Charsets.US_ASCII))
        )

        // the authorization endpoint reads the actual query string, so params must be in the URI
        val authorizeUri = UriComponentsBuilder.fromPath("/oauth2/authorize")
            .queryParam("response_type", "code")
            .queryParam("client_id", "{clientId}")
            .queryParam("redirect_uri", "{redirectUri}")
            .queryParam("state", "test-state")
            .queryParam("code_challenge", codeChallenge)
            .queryParam("code_challenge_method", "S256")
            .buildAndExpand(clientId, REDIRECT_URI)
            .toUri()

        val authorizeResult = mockMvc.perform(get(authorizeUri).with(user("demo")))
            .andExpect(status().is3xxRedirection)
            .andReturn()

        val location = authorizeResult.response.getHeader("Location")!!
        assert(location.startsWith(REDIRECT_URI))
        val code = Regex("[?&]code=([^&]+)").find(location)?.groupValues?.get(1)
        assert(code != null)

        mockMvc.perform(
            post("/oauth2/token")
                .param("grant_type", "authorization_code")
                .param("code", code!!)
                .param("redirect_uri", REDIRECT_URI)
                .param("client_id", clientId)
                .param("code_verifier", codeVerifier)
                .with(csrf())
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.access_token").exists())
            .andExpect(jsonPath("$.token_type").value("Bearer"))
    }
}
