package top.flobby.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author : Flobby
 * @program : spring-security-study
 * @description : 测试接口
 * @create : 2023-05-04 19:43
 **/

@RestController
public class TestController {

    @GetMapping("/test")
    public Object test() {
        return "Hello Security";
    }
}
