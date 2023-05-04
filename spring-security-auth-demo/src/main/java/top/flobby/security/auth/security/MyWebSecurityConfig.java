package top.flobby.security.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import top.flobby.security.auth.handler.JsonAuthenticationFailureHandler;
import top.flobby.security.auth.handler.JsonAuthenticationSuccessHandler;

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

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // 配置所有的Http请求必须认证
        http.authorizeHttpRequests()
                .requestMatchers("/**.html").permitAll()
                .anyRequest().authenticated();
        // 开启表单登录
        http.formLogin()
                // 登录成功处理器
                .successHandler(new JsonAuthenticationSuccessHandler())
                // 登录失败处理器
                .failureHandler(new JsonAuthenticationFailureHandler())
                // .defaultSuccessUrl("/success.html")     // 自定义登录成功页面
                // .failureUrl("/failure.html")    // 自定义登录失败页面
                .loginPage("/login.html")               // 自定义登录页面（注意要同步配置loginProcessingUrl）
                .loginProcessingUrl("/custom/login")    // 自定义登录处理URL
                .usernameParameter("name")              // 自定义用户名参数名称
                .passwordParameter("pwd");              //自定义密码参数名称
        // 关闭 CSRF
        http.csrf().disable();
        return http.build();
    }
}
