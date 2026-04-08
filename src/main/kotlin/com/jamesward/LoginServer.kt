package com.jamesward

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import gg.jte.generated.precompiled.StaticTemplates
import org.springaicommunity.mcp.security.authorizationserver.config.McpAuthorizationServerConfigurer.mcpAuthorizationServer
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.http.MediaType
import org.springframework.security.config.Customizer
import org.springframework.security.config.ObjectPostProcessor
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationProvider
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.converter.OAuth2ClientRegistrationRegisteredClientConverter
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.WebAttributes
import org.springframework.security.web.csrf.CsrfToken
import org.springframework.web.servlet.function.ServerResponse
import org.springframework.web.servlet.function.attributeOrNull
import org.springframework.web.servlet.function.principalOrNull
import org.springframework.web.servlet.function.router
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.time.Duration
import java.util.*


@SpringBootApplication
class LoginServer {

    private val logger = org.slf4j.LoggerFactory.getLogger(LoginServer::class.java)

    @Bean
    fun routes() = router {
        GET("/") { request ->
            val username = request.principalOrNull()?.name
            if (username == null) {
                val uri = request.uriBuilder().path("/login").build()
                ServerResponse.seeOther(uri).build()
            }
            else {
                val page = Page("Sample Auth Server", "You are logged in")
                val homeContent = StaticTemplates().home(username)
                ServerResponse.ok().contentType(MediaType.TEXT_HTML)
                    .body(StaticTemplates().layout(page, homeContent).render())
            }
        }

        GET("/login") { request ->
            val page = Page("Login", "Please enter your username & password")
            val csrfToken = request.attributeOrNull(CsrfToken::class.java.name) as? CsrfToken
            val session = request.session()
            val errorMessage = (session.getAttribute("loginError") as? String) ?: run {
                val maybeException = session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION)
                if (maybeException is Exception) {
                    maybeException.message
                } else {
                    null
                }
            }
            session.removeAttribute("loginError")
            session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION)
            if (csrfToken == null) {
                throw IllegalStateException("No CSRF token found")
            }
            else {
                val loginContent = StaticTemplates().login(csrfToken.token, errorMessage)
                ServerResponse.ok().contentType(MediaType.TEXT_HTML)
                    .body(StaticTemplates().layout(page, loginContent).render())
            }
        }
    }

    val noConsent: ObjectPostProcessor<OAuth2AuthorizationCodeRequestAuthenticationProvider> = object :
        ObjectPostProcessor<OAuth2AuthorizationCodeRequestAuthenticationProvider> {
        override fun <O : OAuth2AuthorizationCodeRequestAuthenticationProvider?> postProcess(
            objectToPostProcess: O?
        ): O? {
            if (objectToPostProcess is OAuth2AuthorizationCodeRequestAuthenticationProvider) {
                objectToPostProcess.setAuthorizationConsentRequired { false }
            }
            return objectToPostProcess
        }
    }

    val longerTTL: ObjectPostProcessor<OAuth2ClientRegistrationAuthenticationProvider> = object :
        ObjectPostProcessor<OAuth2ClientRegistrationAuthenticationProvider> {
        override fun <O : OAuth2ClientRegistrationAuthenticationProvider?> postProcess(
            objectToPostProcess: O?
        ): O? {
            if (objectToPostProcess is OAuth2ClientRegistrationAuthenticationProvider) {
                objectToPostProcess.setRegisteredClientConverter { source ->
                    val registeredClient = OAuth2ClientRegistrationRegisteredClientConverter().convert(source)
                    val tokenSettings = TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofDays(365))
                        .build()
                    RegisteredClient.from(registeredClient).tokenSettings(tokenSettings).build()
                }
            }
            return objectToPostProcess
        }
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder()
    }

    @Bean
    fun userDetailsService(passwordEncoder: PasswordEncoder): UserDetailsService {
        val userBuilder = User.builder().password(passwordEncoder.encode("pw")).roles("USER")

        val james = userBuilder.username("james").build()
        val josh = userBuilder.username("josh").build()
        val rob = userBuilder.username("rob").build()
        val demo = userBuilder.username("demo").build()

        return InMemoryUserDetailsManager(james, josh, rob, demo)
    }

    @Bean
    fun securityFilterChain(http: HttpSecurity): org.springframework.security.web.SecurityFilterChain {
        http
            .authorizeHttpRequests {
                it.requestMatchers("/login", "/webjars/**").permitAll()
                    .anyRequest().authenticated()
            }
            .formLogin {
                it.loginPage("/login")
                    .permitAll()
            }
            .with(mcpAuthorizationServer().authorizationServer { authServer ->
                // gets the correct ordering for disabling consent
                authServer.addObjectPostProcessor(noConsent)
                authServer.addObjectPostProcessor(longerTTL)
                // no matter what scopes the client asks for, we are ok with it
                authServer.authorizationEndpoint { endpoint ->
                    endpoint.authenticationProviders { providers ->
                        providers.filterIsInstance<OAuth2AuthorizationCodeRequestAuthenticationProvider>()
                            .forEach { provider ->
                                provider.setAuthenticationValidator { }
                            }
                    }
                }
            }, Customizer.withDefaults())

        return http.build()
    }

    @Bean
    @ConditionalOnProperty("jwk.rsa.private-key")
    fun jwkSource(@Value($$"${jwk.rsa.private-key}") privateKeyPem: String): JWKSource<SecurityContext> {
        logger.info("Generating JWK from private key")

        val keyBytes = Base64.getDecoder().decode(
            privateKeyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("\\s".toRegex(), "")
        )
        val keyFactory = KeyFactory.getInstance("RSA")
        val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyBytes)) as RSAPrivateCrtKey
        val publicKey = keyFactory.generatePublic(RSAPublicKeySpec(privateKey.modulus, privateKey.publicExponent)) as RSAPublicKey
        val rsaKey = RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyIDFromThumbprint()
            .build()
        return ImmutableJWKSet(JWKSet(rsaKey))
    }

}

data class Page(val title: String, val description: String)

fun main(args: Array<String>) {
    runApplication<LoginServer>(*args)
}
