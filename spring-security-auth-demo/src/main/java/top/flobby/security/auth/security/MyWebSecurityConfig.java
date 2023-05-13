package top.flobby.security.auth.security;

import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import cn.hutool.json.JSONUtil;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.*;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import top.flobby.security.auth.handler.JsonAuthenticationFailureHandler;
import top.flobby.security.auth.handler.JsonAuthenticationSuccessHandler;
import top.flobby.security.auth.handler.JsonLogoutSuccessHandler;
import top.flobby.security.auth.handler.MyLogoutHandler;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

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

    @Resource
    DataSource dataSource;
    @Resource
    UserDetailsService userDetailsService;

    /**
     * 密码器
     */
    // @Bean
    // PasswordEncoder passwordEncoder() {
    //     return new BCryptPasswordEncoder();
    // }

    /**
     * 指定加密算法
     * @return sm4
     */
    // @Bean
    // SM4PasswordEncoder passwordEncoder() {
    //     return new SM4PasswordEncoder("1234567812345678");
    // }

    public class SM4PasswordEncoder implements PasswordEncoder {
        private final SymmetricCrypto sm4;

        public SM4PasswordEncoder(String key) {
            // hutool SmUtil
            // key必须是16字节，即128位：1234567812345678
            this.sm4 = SmUtil.sm4(key.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public String encode(CharSequence rawPassword) {
            return sm4.encryptHex(rawPassword.toString());
        }

        @Override
        public boolean matches(CharSequence rawPassword, String encodedPassword) {
            return sm4.encryptHex(rawPassword.toString()).equals(encodedPassword);
        }
    }

    /**
     * 灵活配置加密算法
     * @return PasswordEncoder
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        // 当前需升级到哪种算法 （实际开发需要在配置文件中读取）
        String encodingId = "bcrypt";
        // 添加算法支持
        Map<String, PasswordEncoder> encoders = new HashMap();
        encoders.put("bcrypt", new BCryptPasswordEncoder());
        encoders.put("ldap", new LdapShaPasswordEncoder());
        encoders.put("MD4", new Md4PasswordEncoder());
        encoders.put("MD5", new MessageDigestPasswordEncoder("MD5"));
        encoders.put("noop", NoOpPasswordEncoder.getInstance());
        encoders.put("pbkdf2", Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_5());
        encoders.put("pbkdf2@SpringSecurity_v5_8", Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8());
        encoders.put("scrypt", SCryptPasswordEncoder.defaultsForSpringSecurity_v4_1());
        encoders.put("scrypt@SpringSecurity_v5_8", SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8());
        encoders.put("SHA-1", new MessageDigestPasswordEncoder("SHA-1"));
        encoders.put("SHA-256", new MessageDigestPasswordEncoder("SHA-256"));
        encoders.put("sha256", new StandardPasswordEncoder());
        encoders.put("argon2", Argon2PasswordEncoder.defaultsForSpringSecurity_v5_2());
        encoders.put("argon2@SpringSecurity_v5_8", Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8());
        // 添加自定义密码编码器
        encoders.put("SM4", new SM4PasswordEncoder("1234567812345678"));
        return new DelegatingPasswordEncoder(encodingId, encoders);
    }

    // 基于数据库存储，并且每次自动登录后修改Cookie
    @Bean
    public RememberMeServices rememberMeServices() {
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl(); // 数据库存储令牌
        tokenRepository.setDataSource(dataSource);
        tokenRepository.setCreateTableOnStartup(true); //启动时自动创建表结构
        return new PersistentTokenBasedRememberMeServices(UUID.randomUUID().toString(), userDetailsService, tokenRepository);
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
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
                // .loginPage("/login.html")               // 自定义登录页面（注意要同步配置loginProcessingUrl）
                .loginProcessingUrl("/custom/login")    // 自定义登录处理URL
                .usernameParameter("name")              // 自定义用户名参数名称
                .passwordParameter("pwd");              // 自定义密码参数名称
        // 注销登录
        http.logout()
                .addLogoutHandler(new MyLogoutHandler())    // 自定义注销处理器
                .logoutSuccessHandler(new JsonLogoutSuccessHandler()) //  自定义注销成功处理器
                .clearAuthentication(true) // 清理Authentication ，默认true
                .deleteCookies("JSESSIONID") // 删除某些指定 cookie
                .invalidateHttpSession(true) // 设置当前登录用户Session（保存登录后的用户信息）无效，默认true
                // 自定义注销请求URL（和 logoutUrl配置只会生效一个）
                .logoutRequestMatcher(new OrRequestMatcher(
                        new AntPathRequestMatcher("/aaa", "GET"),
                        new AntPathRequestMatcher("/bbb", "GET")))
                .logoutSuccessUrl("/success.html"); // 自定义注销成功跳转地址
                // 自定义注销登录请求处理路径
                // .logoutUrl("/custom/logout");
                // 关闭注销登录
                // .disable();
        // 会话创建策略
        http.sessionManagement()
                // .invalidSessionUrl("/login‐view?error=INVALID_SESSION") // 失效跳转路径
                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS) // 创建策略
                .maximumSessions(1) // 用户最大会话数为 1，后面的登陆就会自动踢掉前面的登陆
                .maxSessionsPreventsLogin(true) // 当前已登录时，阻止其他登录
                .expiredSessionStrategy(event -> { //  会话失效策略
                    HttpServletResponse response = event.getResponse();
                    response.setContentType("application/json;charset=utf-8"); // 返回JSON
                    response.setStatus(HttpStatus.BAD_REQUEST.value());  // 状态码
                    Map<String, Object> result = new HashMap<>(); // 返回结果
                    result.put("msg", "当前会话已失效");
                    result.put("code", 401);
                    response.getWriter().write(JSONUtil.toJsonStr(result));
                });
        // http.sessionManagement(session -> session
        //         .sessionFixation( // 会话固定攻击保护策略
        //                 SessionManagementConfigurer.SessionFixationConfigurer::changeSessionId
        //         ));
        // 开启记住我
        /* http.rememberMe()
                //.alwaysRemember(true) // 始终开启记住我，不校验参数
                .rememberMeParameter("my-param")  // 修改参数名，默认remember-me
                .useSecureCookie(false) // 是否只支持https
                .rememberMeCookieDomain("127.0.0.1") // 可以访问该 cookie 的域名
                .rememberMeCookieName("my-cookie-name") // 配置自定义Cookie 名，默认 remember-me
                .tokenValiditySeconds(60 * 60 * 24 * 7); // 记住我有效时间
                */
        // 开启 Basic 认证
        http.httpBasic();
        // 关闭 CSRF
        http.csrf().disable();
        // 开启记住我
        http.rememberMe()
                .rememberMeServices(rememberMeServices()); // 自定义记住我服务类
        return http.build();
    }
}
