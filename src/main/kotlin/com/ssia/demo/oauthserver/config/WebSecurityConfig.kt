package com.ssia.demo.oauthserver.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager

@Configuration
class WebSecurityConfig : WebSecurityConfigurerAdapter() {

    @Bean
    fun uds(): InMemoryUserDetailsManager {
        val uds = InMemoryUserDetailsManager()
        val userDetails = User.withUsername("john").password("password").authorities("read").build()
        uds.createUser(userDetails)
        return uds
    }

    @Bean
    fun passwordEncoder() = NoOpPasswordEncoder.getInstance()

    @Bean
    override fun authenticationManagerBean(): AuthenticationManager? {
        return super.authenticationManager()
    }

    override fun configure(http: HttpSecurity?) {
        http {
            formLogin {  }
        }
    }
}