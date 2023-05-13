package top.flobby.security;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import top.flobby.security.auth.entity.User;
import top.flobby.security.auth.service.IUserService;

@SpringBootTest
@Slf4j
class SpringSecurityAuthDemoApplicationTest {
    @Autowired
    IUserService userService;

    @Test
    @DisplayName("根据用户名查询用户")
    void testMp() {
        User admin = userService.getOne(new LambdaQueryWrapper<User>().eq(User::getUserName, "admin"));
        log.info(String.valueOf(admin));
    }

    @Test
    @DisplayName("插入用户数据")
    void insertUserTest1() {
        User user = new User();
        user.setUserName("bcrypt");
        // 使用 bcrypt 加密
        user.setPassword(new BCryptPasswordEncoder().encode("123456"));
        user.setLoginName("bcrypt");
        user.setPhone("13188888888");
        userService.save(user);


        User user2 = new User();
        user2.setUserName("argon2");
        // 使用 argon2 加密
        Argon2PasswordEncoder arg2SpringSecurity = new Argon2PasswordEncoder(16, 32, 1, 65536, 10);
        user2.setPassword(arg2SpringSecurity.encode("123456"));
        user2.setLoginName("argon2");
        user2.setPhone("13388888888");
        userService.save(user2);
    }
}