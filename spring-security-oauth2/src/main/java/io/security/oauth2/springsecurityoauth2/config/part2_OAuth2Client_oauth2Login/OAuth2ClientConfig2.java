package io.security.oauth2.springsecurityoauth2.config.part2_OAuth2Client_oauth2Login;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@EnableWebSecurity
@RequiredArgsConstructor
public class OAuth2ClientConfig2 {

    private final ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        //http.authorizeRequests().anyRequest().authenticated();
        http.authorizeRequests(authRequest -> authRequest
                //.antMatchers("/loginPage")
                //.permitAll()
                .anyRequest()
                .authenticated()
        );

        http.oauth2Login(oauth2 -> oauth2.loginPage("/login")
            .authorizationEndpoint(authorizationEndpointConfig ->
                    authorizationEndpointConfig.baseUri("/oauth2/v1/authorization"))
        );

//        http.oauth2Login(oauth2 -> oauth2.loginPage("/loginPage"));
        http.oauth2Login(Customizer.withDefaults());
        http.logout()
                .logoutSuccessHandler(oidcLogoutSuccessHandler())
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID");

        return http.build();
    }

    private LogoutSuccessHandler oidcLogoutSuccessHandler() {

        OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        successHandler.setPostLogoutRedirectUri("http://localhost:8081/login");

        return successHandler;
    }


}
