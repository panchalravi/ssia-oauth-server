package com.ssia.demo.oauthserver.config

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.io.ClassPathResource
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory

@Configuration
@EnableAuthorizationServer
class AuthServerConfig(val authenticationManager: AuthenticationManager) : AuthorizationServerConfigurerAdapter() {

    @Value("\${jwt.key}")
    lateinit var jwtKey: String

    @Value("\${password}")
    lateinit var password: String

    @Value("\${privateKey}")
    lateinit var privateKey: String

    @Value("\${alias}")
    lateinit var alias: String

    override fun configure(endpoints: AuthorizationServerEndpointsConfigurer?) {
        endpoints?.apply {
            authenticationManager(authenticationManager)
            tokenStore(tokenStore())
            accessTokenConverter(jwtAccessTokenConverter())
        }
    }

    override fun configure(security: AuthorizationServerSecurityConfigurer?) {
        security?.checkTokenAccess("isAuthenticated()")
            ?.tokenKeyAccess("isAuthenticated()")
    }

    override fun configure(clients: ClientDetailsServiceConfigurer?) {
        clients?.apply {
            inMemory()
                .withClient("client")
                .secret("secret")
                .authorizedGrantTypes("authorization_code")
                .scopes("read")
                .redirectUris("http://localhost:9090/home")
                .and()

                .withClient("client2")
                .secret("secret")
                .authorizedGrantTypes("authorization_code", "password", "refresh_token")
                .scopes("read")
                .redirectUris("http://localhost:9090/home")

                .and()
                .withClient("client3")
                .secret("secret")
                .authorizedGrantTypes("client_credentials")
                .scopes("info")

                .and()
                .withClient("resourceserver")
                .secret("secret")
        }
    }

    @Bean
    fun tokenStore(): TokenStore = JwtTokenStore(jwtAccessTokenConverter())

    //Sign JWT using symmetric key
    /*
    @Bean
    fun jwtAccessTokenConverter(): JwtAccessTokenConverter {
        val converter = JwtAccessTokenConverter()
        converter.setSigningKey(jwtKey)
        return converter
    }
    */

    //Sign JWT using asymmetric key
    @Bean
    fun jwtAccessTokenConverter(): JwtAccessTokenConverter {
        val converter = JwtAccessTokenConverter()
        val keyStoreKeyFactory = KeyStoreKeyFactory(ClassPathResource(privateKey), password.toCharArray())
        converter.setKeyPair(keyStoreKeyFactory.getKeyPair(alias))
        return converter
    }
}