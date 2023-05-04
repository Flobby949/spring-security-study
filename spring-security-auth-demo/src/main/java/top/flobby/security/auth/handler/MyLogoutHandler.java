package top.flobby.security.auth.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

/**
 * @author : Flobby
 * @program : spring-security-study
 * @description : 自定义注销处理器
 * @create : 2023-05-04 21:04
 **/

public class MyLogoutHandler implements LogoutHandler {
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        System.out.println("-------自定义注销处理器--------");
    }
}
