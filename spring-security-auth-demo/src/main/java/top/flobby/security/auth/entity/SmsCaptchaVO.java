package top.flobby.security.auth.entity;

import lombok.Data;

import java.io.Serializable;

/**
 * @author : Flobby
 * @program : spring-security-study
 * @description : 短信验证码
 * @create : 2023-05-13 15:51
 **/

@Data
public class SmsCaptchaVO implements Serializable {
    /**
     * 手机号
     */
    private String phone;
    /**
     * 多少分钟后过期
     */
    private Integer expire;
}
