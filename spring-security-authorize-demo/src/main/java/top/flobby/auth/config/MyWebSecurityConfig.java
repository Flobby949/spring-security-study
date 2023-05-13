package top.flobby.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;

/**
 * @author : Flobby
 * @program : spring-security-study
 * @description : security配置
 * @create : 2023-05-13 16:04
 **/

@Configuration
@EnableWebSecurity(debug = false)
public class MyWebSecurityConfig {

    @Bean
    UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager detailsManager = new InMemoryUserDetailsManager();
        // 创建管理员
        detailsManager.createUser(User.withUsername("admin").password("{noop}123456").roles("ADMIN").build());
        // 创建用户
        detailsManager.createUser(User.withUsername("user").password("{noop}123456").roles("USER").build());
        return detailsManager;
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // 配置所有的Http请求必须认证
        http.authorizeHttpRequests()
                // permitAll 指定放行
                .requestMatchers("/resources/**", "/signup", "/about").permitAll()
                // 以 user 开头的请求，必须拥有 ADMIN 角色
                .requestMatchers("/user/**").hasRole("ADMIN")
                // db 开头的请求，必须同时拥有 ADMIN 和 DBA 权限
                .requestMatchers("/db/**").access(new WebExpressionAuthorizationManager("hasRole('ADMIN') and hasRole('DBA')"))
                .anyRequest()
                .authenticated();
        // 开启表单登录
        http.formLogin();
        // 开启Basic认证
        http.httpBasic();
        // 关闭 CSRF
        http.csrf().disable();
        return http.build();
    }
}
