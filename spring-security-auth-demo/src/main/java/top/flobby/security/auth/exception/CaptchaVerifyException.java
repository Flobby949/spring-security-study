package top.flobby.security.auth.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * @author : Flobby
 * @program : spring-security-study
 * @description : 验证码异常
 * @create : 2023-05-13 15:37
 **/

public class CaptchaVerifyException extends AuthenticationException {

    public CaptchaVerifyException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public CaptchaVerifyException(String msg) {
        super(msg);
    }
}
