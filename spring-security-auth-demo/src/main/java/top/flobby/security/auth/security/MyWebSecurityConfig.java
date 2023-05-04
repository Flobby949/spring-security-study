package top.flobby.security.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import top.flobby.security.auth.handler.JsonAuthenticationFailureHandler;
import top.flobby.security.auth.handler.JsonAuthenticationSuccessHandler;
import top.flobby.security.auth.handler.JsonLogoutSuccessHandler;
import top.flobby.security.auth.handler.MyLogoutHandler;

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
                .requestMatchers("/**.html", "/aaa", "/bbb").permitAll()
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
        // 注销登录
        http.logout()
                .addLogoutHandler(new MyLogoutHandler())    // 自定义注销处理器
                .logoutSuccessHandler(new JsonLogoutSuccessHandler()) //  自定义注销成功处理器
                .clearAuthentication(true) // 清理Authentication ，默认true
                // .deleteCookies("xxx", "yyy") // 删除某些指定 cookie
                .invalidateHttpSession(true) // 设置当前登录用户Session（保存登录后的用户信息）无效，默认true
                // 自定义注销请求URL（和 logoutUrl配置只会生效一个）
                .logoutRequestMatcher(new OrRequestMatcher(
                        new AntPathRequestMatcher("/aaa","GET"),
                        new AntPathRequestMatcher("/bbb","GET")))
                .logoutSuccessUrl("/success.html"); // 自定义注销成功跳转地址
                // 自定义注销登录请求处理路径
                // .logoutUrl("/custom/logout");
                // 关闭注销登录
                // .disable();
        // 开启 Basic 认证
        http.httpBasic();
        // 关闭 CSRF
        http.csrf().disable();
        return http.build();
    }
}
