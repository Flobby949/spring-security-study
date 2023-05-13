package top.flobby.security.auth.common;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author : Flobby
 * @program : spring-security-study
 * @description : 统一响应
 * @create : 2023-05-13 15:35
 **/

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class R<T> {

    /**
     * 状态码
     */
    private Integer code;

    /**
     * 返回信息
     */
    private String msg;

    /**
     * 数据
     */
    private T data;

    public static <T> R<T> response(Integer code, String msg, T data) {
        R<T> result = new R<>();
        result.setCode(code);
        result.setMsg(msg);
        result.setData(data);
        return result;
    }

    public static <T> R<T> success() {
        return response(ResultCodeEnum.SUCCESS.getCode(), ResultCodeEnum.SUCCESS.getMsg(), null);
    }

    public static <T> R<T> fail() {
        return response(ResultCodeEnum.FAIL.getCode(), ResultCodeEnum.FAIL.getMsg(), null);
    }
}

