package top.flobby.security.auth.sms;

import org.springframework.context.ApplicationContext;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import top.flobby.security.auth.filter.SmsAuthenticationFilter;
import top.flobby.security.auth.handler.JsonAuthenticationFailureHandler;
import top.flobby.security.auth.handler.JsonAuthenticationSuccessHandler;
import top.flobby.security.auth.service.impl.UserDetailsServiceImpl;

/**
 * @author : Flobby
 * @program : spring-security-study
 * @description : 短信认证配置
 * @create : 2023-05-13 15:55
 **/

public class SmsLoginConfigurer extends AbstractHttpConfigurer<SmsLoginConfigurer, HttpSecurity> {

    @Override
    public void init(HttpSecurity http) throws Exception {
        // 初始化方法
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        // 配置方法
        // 添加认证提供者
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        UserDetailsServiceImpl userDetailService = http.getSharedObject(ApplicationContext.class).getBean(UserDetailsServiceImpl.class);
        StringRedisTemplate stringRedisTemplate = http.getSharedObject(ApplicationContext.class).getBean(StringRedisTemplate.class);
        http.authenticationProvider(new SmsAuthenticationProvider(userDetailService, stringRedisTemplate));
        // 添加过滤器
        SmsAuthenticationFilter filter = new SmsAuthenticationFilter();
        filter.setAuthenticationSuccessHandler(new JsonAuthenticationSuccessHandler());
        filter.setAuthenticationFailureHandler(new JsonAuthenticationFailureHandler());
        filter.setAuthenticationManager(authenticationManager);
        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
    }

    public static SmsLoginConfigurer smsLogin() {
        return new SmsLoginConfigurer();
    }
}
