package top.flobby.security.auth.mp;

import com.baomidou.mybatisplus.generator.FastAutoGenerator;
import com.baomidou.mybatisplus.generator.config.OutputFile;
import com.baomidou.mybatisplus.generator.engine.FreemarkerTemplateEngine;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Collections;

/**
 * @author : Flobby
 * @program : spring-security-study
 * @description : 代码生成器工具
 * @create : 2023-05-04 19:51
 **/

public class AutoGeneratorUtils {

    public static void main(String[] args) {
        String encode = new BCryptPasswordEncoder().encode("kobe24");
        System.out.println(encode);
        FastAutoGenerator.create("jdbc:mysql://127.0.0.1:3306/db_security_study", "root", "kobe24")
                .globalConfig(builder -> {
                    builder.author("flobby") // 设置作者
                            .outputDir("E:\\java-projects\\spring-security-study\\spring-security-auth-demo\\src\\main\\java"); // 指定输出目录
                })
                .packageConfig(builder -> {
                    builder.parent("top.flobby.security") // 设置父包名
                            .moduleName("auth") // 设置父包模块名
                            .pathInfo(Collections.singletonMap(OutputFile.xml, "E:\\java-projects\\spring-security-study\\spring-security-auth-demo\\src\\main\\resources\\mapper")); // 设置mapperXml生成路径
                })
                .strategyConfig(builder -> {
                    builder.addInclude("user") // 设置需要生成的表名
                            .addTablePrefix("t_", "sys_"); // 设置过滤表前缀
                })
                .templateEngine(new FreemarkerTemplateEngine()) // 使用Freemarker引擎模板，默认的是Velocity引擎模板
                .execute();
    }
}