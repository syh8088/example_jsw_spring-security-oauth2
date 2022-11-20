package io.security.oauth2.springsecurityoauth2.config.part2_OAuth2Client_oauth2Login;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController2 {

    @GetMapping("/loginPage")
    public String loginPage2() {
        return "loginPage";
    }
}
