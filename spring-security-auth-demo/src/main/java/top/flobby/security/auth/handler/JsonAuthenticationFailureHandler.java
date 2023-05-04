package top.flobby.security.auth.handler;

import cn.hutool.json.JSONUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author : Flobby
 * @program : spring-security-study
 * @description : 自定义登录失败处理器
 * @create : 2023-05-04 20:52
 **/

public class JsonAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8"); // 返回JSON
        response.setStatus(HttpStatus.BAD_REQUEST.value());  // 状态码 400
        Map<String, Object> result = new HashMap<>(); // 返回结果
        result.put("msg", "登录失败");
        result.put("code", 400);
        result.put("data", exception.getMessage());
        response.getWriter().write(JSONUtil.toJsonStr(result));
    }
}