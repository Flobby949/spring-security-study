package top.flobby.security.auth.entity;

import lombok.Data;

import java.io.Serializable;

/**
 * @author : Flobby
 * @program : spring-security-study
 * @description : 验证码
 * @create : 2023-05-13 15:32
 **/

@Data
public class CaptchaVO implements Serializable {
    // 唯一ID
    private String id;
    // 验证码图片 Base64
    private String base64;
}
