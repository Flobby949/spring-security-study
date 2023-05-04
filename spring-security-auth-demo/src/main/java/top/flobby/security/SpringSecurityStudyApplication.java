package top.flobby.security;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author : Flobby
 * @program : spring-security-study
 * @description : spring security 学习
 * @create : 2023-05-04 19:37
 **/

@SpringBootApplication
@MapperScan("top.flobby.security.auth.mapper")
public class SpringSecurityStudyApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityStudyApplication.class, args);
    }
}
