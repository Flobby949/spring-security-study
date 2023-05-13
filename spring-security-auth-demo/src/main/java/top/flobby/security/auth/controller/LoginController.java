package top.flobby.security.auth.controller;

import com.wf.captcha.SpecCaptcha;
import com.wf.captcha.base.Captcha;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import top.flobby.security.auth.common.R;
import top.flobby.security.auth.entity.CaptchaVO;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * @author : Flobby
 * @program : spring-security-study
 * @description : 登录接口
 * @create : 2023-05-13 15:35
 **/

@Controller
@Slf4j
public class LoginController {

    @Resource
    private StringRedisTemplate stringRedisTemplate;

    @GetMapping("/generateCaptcha")
    @ResponseBody
    public R<CaptchaVO> getCaptcha() {
        SpecCaptcha captcha = new SpecCaptcha(150, 40);
        log.info("生成验证码：" + captcha.text());
        captcha.setLen(5);
        captcha.setCharType(Captcha.TYPE_DEFAULT);
        String image = captcha.toBase64();
        CaptchaVO captchaVO = new CaptchaVO();
        String code = UUID.randomUUID().toString();
        captchaVO.setId(code);
        captchaVO.setBase64(image);
        // 缓存验证码，10分钟有效
        stringRedisTemplate.opsForValue().set(captchaVO.getId(), captcha.text(), 10, TimeUnit.MINUTES);
        return R.response(200, "生成验证码成功", captchaVO);
    }
}

