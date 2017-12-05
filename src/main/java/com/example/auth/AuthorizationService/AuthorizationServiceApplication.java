package com.example.auth.AuthorizationService;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@SpringBootApplication
@EnableResourceServer
@EnableAuthorizationServer
@SessionAttributes("authorizationRequest")
public class AuthorizationServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServiceApplication.class, args);
	}
}


@RestController
@RequestMapping("/user")
class authController {

	@GetMapping("")
	@ResponseBody
	public Principal user(Principal user) {
		return user;
	}
}


@Configuration
class OAuthConfig extends AuthorizationServerConfigurerAdapter {

	private AuthenticationManager authenticationManager;

	public OAuthConfig(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
				.authenticationManager(this.authenticationManager)
				.tokenStore(tokenStore());
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer)
			throws Exception {
		oauthServer
				.tokenKeyAccess("permitAll()")
				.checkTokenAccess("isAuthenticated()");
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory()
				.withClient("ui1")
				.secret("ui1-secret")
				.authorities("ROLE_TRUSTED_CLIENT")
				.authorizedGrantTypes("authorization_code", "refresh_token")
				.scopes("ui1.read")
				.autoApprove(true)
				.and()
				.withClient("ui2")
				.secret("ui2-secret")
				.authorities("ROLE_TRUSTED_CLIENT")
				.authorizedGrantTypes("authorization_code", "refresh_token")
				.scopes("ui2.read", "ui2.write")
				.autoApprove(true)
				.and()
				.withClient("mobile-app")
				.authorities("ROLE_CLIENT")
				.authorizedGrantTypes("implicit", "refresh_token")
				.scopes("read")
				.autoApprove(true)
				.and()
				.withClient("customer-integration-system")
				.secret("1234567890")
				.authorities("ROLE_CLIENT")
				.authorizedGrantTypes("client_credentials")
				.scopes("read")
				.autoApprove(true);
	}

	@Bean
	public InMemoryTokenStore tokenStore() {
		return new InMemoryTokenStore();
	}
}


@Configuration
@EnableWebSecurity
class webSecurityConfig extends WebSecurityConfigurerAdapter {

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
				.withUser("steve").password("password").roles("END_USER","CLIENT")
				.and()
				.withUser("admin").password("admin").roles("ADMIN");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.requestMatchers().antMatchers( "/oauth/authorize", "/oauth/confirm_access")
				.and()
				.authorizeRequests().anyRequest().authenticated();
	}
}


//.formLogin().permitAll()
//		.and()
//		.requestMatchers().antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access")
//		.and()