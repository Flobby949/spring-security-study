package top.flobby.security.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author : Flobby
 * @program : spring-security-study
 * @description : 配置类
 * @create : 2023-05-04 20:03
 **/

@Configuration
// 开启 Spring Security，debug：是否开启Debug模式
@EnableWebSecurity(debug = false)
public class MyWebSecurityConfig {

    /**
     * 密码器
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
