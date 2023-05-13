package top.flobby.security.auth.sms;

import cn.hutool.core.util.StrUtil;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import top.flobby.security.auth.service.impl.UserDetailsServiceImpl;

/**
 * @author : Flobby
 * @program : spring-security-study
 * @description : 认证提供者
 * @create : 2023-05-13 15:54
 **/

public class SmsAuthenticationProvider implements AuthenticationProvider {
    private final UserDetailsServiceImpl userDetailsServiceImpl;

    private final StringRedisTemplate stringRedisTemplate;
    ;

    public SmsAuthenticationProvider(UserDetailsServiceImpl userDetailsServiceImpl, StringRedisTemplate stringRedisTemplate) {
        this.userDetailsServiceImpl = userDetailsServiceImpl;
        this.stringRedisTemplate = stringRedisTemplate;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        SmsAuthenticationToken authenticationToken = (SmsAuthenticationToken) authentication;
        Object principal = authentication.getPrincipal();// 获取凭证也就是用户的手机号
        String phone = "";
        if (principal instanceof String) {
            phone = (String) principal;
        }
        String inputCode = (String) authentication.getCredentials(); // 获取输入的验证码
        // 1. 检验Redis手机号的验证码
        String redisCode = stringRedisTemplate.opsForValue().get(phone);
        if (StrUtil.isEmpty(redisCode)) {
            throw new BadCredentialsException("验证码已经过期或尚未发送，请重新发送验证码");
        }
        if (!inputCode.equals(redisCode)) {
            throw new BadCredentialsException("输入的验证码不正确，请重新输入");
        }
        // 2. 根据手机号查询用户信息
        UserDetails userDetails = userDetailsServiceImpl.loadUserByPhone(phone);
        if (userDetails == null) {
            throw new InternalAuthenticationServiceException("phone用户不存在，请注册");
        }
        // 3. 创建已认证对象
        SmsAuthenticationToken authenticationResult = new SmsAuthenticationToken(principal, inputCode, userDetails.getAuthorities());
        authenticationResult.setDetails(authenticationToken.getDetails());
        return authenticationResult;
    }


    @Override
    public boolean supports(Class<?> aClass) {
        // 当 SmsAuthenticationToken 认证时，匹配该类
        return SmsAuthenticationToken.class.isAssignableFrom(aClass);
    }
}