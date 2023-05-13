package top.flobby.security.auth.common;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * @author : Flobby
 * @program : spring-security-study
 * @description : 状态码枚举
 * @create : 2023-05-13 15:35
 **/

@NoArgsConstructor
@AllArgsConstructor
@Getter
public enum ResultCodeEnum implements StatusCode {

    FAIL(-1, "操作失败"),
    SUCCESS(200, "操作成功");

    private int code;

    private String msg;

    @Override
    public int getCode() {
        return code;
    }

    @Override
    public String getMsg() {
        return msg;
    }
}
