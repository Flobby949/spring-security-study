package top.flobby.auth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author : Flobby
 * @program : spring-security-study
 * @description : 用户接口
 * @create : 2023-05-13 16:04
 **/

@RestController
@RequestMapping("/user")
public class UserController {

    @GetMapping("/save")
    String save() {
        return "save";
    }

    @GetMapping("/del")
    String del() {
        return "del";
    }

    @GetMapping("/update")
    String update() {
        return "update";
    }

    @GetMapping("/list")
    String list() {
        return "list";
    }
}
