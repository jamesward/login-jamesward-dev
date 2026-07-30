package com.jamesward

import tools.jackson.databind.ObjectMapper
import org.springframework.http.MediaType
import org.springframework.http.client.JdkClientHttpRequestFactory
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.web.client.RestClient
import java.net.InetAddress
import java.net.URI
import java.net.http.HttpClient
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

/**
 * A [RegisteredClientRepository] that supports OAuth Client ID Metadata Documents (CIMD,
 * draft-ietf-oauth-client-id-metadata-document) in addition to whatever the delegate holds
 * (statically configured clients and clients registered via Dynamic Client Registration).
 *
 * When a client_id is an HTTPS URL, the metadata document it points to is fetched and
 * converted into a [RegisteredClient] on the fly, so MCP clients can be used without
 * pre-registration or DCR.
 *
 * [allowLoopback] relaxes the HTTPS and loopback-address restrictions so that metadata
 * documents can be served from localhost during development and testing.
 */
class CimdRegisteredClientRepository(
    private val delegate: RegisteredClientRepository,
    private val tokenSettings: TokenSettings,
    private val allowLoopback: Boolean = false,
    private val cacheTtl: Duration = Duration.ofMinutes(5),
) : RegisteredClientRepository {

    private val logger = org.slf4j.LoggerFactory.getLogger(CimdRegisteredClientRepository::class.java)

    private val objectMapper = ObjectMapper()

    // the JDK HttpClient does not follow redirects by default, which is what the spec wants
    private val restClient = RestClient.builder()
        .requestFactory(
            JdkClientHttpRequestFactory(
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()
            ).apply { setReadTimeout(Duration.ofSeconds(5)) }
        )
        .build()

    private data class CacheEntry(val registeredClient: RegisteredClient, val expiresAt: Instant)

    private val cache = ConcurrentHashMap<String, CacheEntry>()

    override fun save(registeredClient: RegisteredClient) {
        delegate.save(registeredClient)
    }

    override fun findById(id: String): RegisteredClient? =
        delegate.findById(id) ?: resolve(id)

    override fun findByClientId(clientId: String): RegisteredClient? =
        delegate.findByClientId(clientId) ?: resolve(clientId)

    private fun resolve(clientId: String): RegisteredClient? {
        val uri = validateClientIdUrl(clientId) ?: return null

        cache[clientId]?.let { entry ->
            if (entry.expiresAt.isAfter(Instant.now())) {
                return entry.registeredClient
            }
            cache.remove(clientId)
        }

        val document = fetchDocument(uri) ?: return null
        val registeredClient = toRegisteredClient(clientId, document) ?: return null

        cache[clientId] = CacheEntry(registeredClient, Instant.now().plus(cacheTtl))
        return registeredClient
    }

    // the client_id URL requirements from draft-ietf-oauth-client-id-metadata-document
    private fun validateClientIdUrl(clientId: String): URI? {
        val uri = try {
            URI(clientId)
        } catch (_: Exception) {
            return null
        }

        val httpsOrLocalHttp = uri.scheme == "https" || (allowLoopback && uri.scheme == "http")
        if (!httpsOrLocalHttp) return null
        if (uri.host.isNullOrEmpty()) return null
        if (uri.userInfo != null) return null
        if (uri.fragment != null) return null
        if (uri.path.isNullOrEmpty() || uri.path == "/") return null
        if (uri.path.split("/").any { it == "." || it == ".." }) return null
        if (!allowLoopback && !isPubliclyRoutable(uri.host)) return null

        return uri
    }

    // SSRF protection: don't fetch from loopback, link-local, or private addresses
    private fun isPubliclyRoutable(host: String): Boolean =
        try {
            InetAddress.getAllByName(host).none { address ->
                address.isLoopbackAddress || address.isSiteLocalAddress || address.isLinkLocalAddress ||
                        address.isAnyLocalAddress || address.isMulticastAddress ||
                        (address.address.size == 16 && (address.address[0].toInt() and 0xfe) == 0xfc)
            }
        } catch (_: Exception) {
            false
        }

    private fun fetchDocument(uri: URI): Map<*, *>? =
        try {
            val body = restClient.get()
                .uri(uri)
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .body(String::class.java)

            if (body == null || body.length > MAX_DOCUMENT_SIZE) {
                null
            } else {
                objectMapper.readValue(body, Map::class.java)
            }
        } catch (e: Exception) {
            logger.debug("Failed to fetch client ID metadata document from {}", uri, e)
            null
        }

    private fun toRegisteredClient(clientId: String, document: Map<*, *>): RegisteredClient? {
        // the document must claim the URL it was fetched from as its client_id
        if (document["client_id"] != clientId) return null

        // shared symmetric secrets are not allowed for URL-based clients
        if (document.containsKey("client_secret")) return null
        val authMethod = when (document["token_endpoint_auth_method"] ?: "none") {
            "none" -> ClientAuthenticationMethod.NONE
            "private_key_jwt" ->
                if (document["jwks_uri"] is String) ClientAuthenticationMethod.PRIVATE_KEY_JWT else return null
            else -> return null
        }

        val grantTypes = ((document["grant_types"] as? List<*>) ?: listOf("authorization_code"))
            .mapNotNull { grantType ->
                when (grantType) {
                    "authorization_code" -> AuthorizationGrantType.AUTHORIZATION_CODE
                    "refresh_token" -> AuthorizationGrantType.REFRESH_TOKEN
                    else -> null
                }
            }
        if (!grantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE)) return null

        val redirectUris = (document["redirect_uris"] as? List<*>)?.filterIsInstance<String>() ?: emptyList()
        if (redirectUris.isEmpty()) return null

        val scopes = (document["scope"] as? String)?.split(" ")?.filter { it.isNotBlank() } ?: emptyList()

        val clientSettings = ClientSettings.builder()
            .requireProofKey(true)
            .requireAuthorizationConsent(false)
            .apply {
                if (authMethod == ClientAuthenticationMethod.PRIVATE_KEY_JWT) {
                    jwkSetUrl(document["jwks_uri"] as String)
                }
            }
            .build()

        return RegisteredClient.withId(clientId)
            .clientId(clientId)
            .clientIdIssuedAt(Instant.now())
            .clientName((document["client_name"] as? String) ?: clientId)
            .clientAuthenticationMethod(authMethod)
            .authorizationGrantTypes { it.addAll(grantTypes) }
            .redirectUris { it.addAll(redirectUris) }
            .scopes { it.addAll(scopes) }
            .clientSettings(clientSettings)
            .tokenSettings(tokenSettings)
            .build()
    }

    companion object {
        // the spec recommends documents stay under 5KB; allow some slack
        private const val MAX_DOCUMENT_SIZE = 16 * 1024
    }
}
