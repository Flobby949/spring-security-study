package top.flobby.security.auth.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import top.flobby.security.auth.entity.User;

@SpringBootTest
class IUserServiceTest {
    @Autowired
    private IUserService userService;

    @Test
    @DisplayName("插入一条用户数据")
    void insertUserTest() {
        User user = new User();
        user.setUserName("admin1");
        user.setPassword(new BCryptPasswordEncoder().encode("123456"));
        user.setLoginName("管理员1");
        user.setPhone("13688888888");
        userService.save(user);
    }

}