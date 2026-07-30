package com.jamesward

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.util.UriComponentsBuilder
import tools.jackson.databind.ObjectMapper
import java.security.MessageDigest
import java.util.*
import kotlin.test.Test

/**
 * MCP clients register for scopes such as `mcp:tools` via Dynamic Client Registration.
 * Spring Security 7.1 rejects any scope at registration by default, so these cover the
 * scope handling that MCP clients depend on.
 */
@SpringBootTest
@AutoConfigureMockMvc
class DcrScopeTest(@Autowired val mockMvc: MockMvc) {

    private val redirectUri = "http://127.0.0.1:8081/callback"

    private fun register(scope: String?): String {
        val registration = buildMap {
            put("client_name", "MCP Test Client")
            put("redirect_uris", listOf(redirectUri))
            put("grant_types", listOf("authorization_code"))
            put("token_endpoint_auth_method", "none")
            if (scope != null) put("scope", scope)
        }

        val response = mockMvc.perform(
            post("/oauth2/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(ObjectMapper().writeValueAsString(registration))
                .with(csrf())
        )
            .andExpect(status().isCreated)
            .andReturn()
            .response
            .contentAsString

        return ObjectMapper().readValue(response, Map::class.java)["client_id"] as String
    }

    @Test
    fun `registration accepts a scope and echoes it back`() {
        mockMvc.perform(
            post("/oauth2/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                      "client_name": "MCP Test Client",
                      "redirect_uris": ["$redirectUri"],
                      "grant_types": ["authorization_code"],
                      "token_endpoint_auth_method": "none",
                      "scope": "mcp:tools"
                    }
                    """.trimIndent()
                )
                .with(csrf())
        )
            .andExpect(status().isCreated)
            .andExpect(jsonPath("$.scope").value("mcp:tools"))
    }

    @Test
    fun `token endpoint issues a token for a registered scope`() {
        val clientId = register("mcp:tools")

        val codeVerifier = "test-code-verifier-test-code-verifier-test-1"
        val codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(codeVerifier.toByteArray(Charsets.US_ASCII))
        )

        val authorizeUri = UriComponentsBuilder.fromPath("/oauth2/authorize")
            .queryParam("response_type", "code")
            .queryParam("client_id", "{clientId}")
            .queryParam("redirect_uri", "{redirectUri}")
            .queryParam("scope", "mcp:tools")
            .queryParam("code_challenge", codeChallenge)
            .queryParam("code_challenge_method", "S256")
            .buildAndExpand(clientId, redirectUri)
            .toUri()

        val location = mockMvc.perform(get(authorizeUri).with(user("demo")))
            .andExpect(status().is3xxRedirection)
            .andReturn()
            .response
            .getHeader("Location")!!

        val code = Regex("[?&]code=([^&]+)").find(location)?.groupValues?.get(1)
        assert(code != null)

        mockMvc.perform(
            post("/oauth2/token")
                .param("grant_type", "authorization_code")
                .param("code", code!!)
                .param("redirect_uri", redirectUri)
                .param("client_id", clientId)
                .param("code_verifier", codeVerifier)
                .with(csrf())
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.access_token").exists())
            .andExpect(jsonPath("$.scope").value("mcp:tools"))
    }

    @Test
    fun `registration still works without a scope`() {
        register(null)
    }
}
