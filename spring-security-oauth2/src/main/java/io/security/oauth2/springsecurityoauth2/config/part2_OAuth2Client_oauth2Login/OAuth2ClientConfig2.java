package io.security.oauth2.springsecurityoauth2.config.part2_OAuth2Client_oauth2Login;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class OAuth2ClientConfig2 {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        //http.authorizeRequests().anyRequest().authenticated();
        http.authorizeRequests(authRequest -> authRequest
                //.antMatchers("/loginPage")
                //.permitAll()
                .anyRequest()
                .authenticated()
        );

//        http.oauth2Login(oauth2 -> oauth2.loginPage("/loginPage"));
        http.oauth2Login(Customizer.withDefaults());

        return http.build();
    }


}
