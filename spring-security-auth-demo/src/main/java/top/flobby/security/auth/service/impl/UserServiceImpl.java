package top.flobby.security.auth.service.impl;

import top.flobby.security.auth.entity.User;
import top.flobby.security.auth.mapper.UserMapper;
import top.flobby.security.auth.service.IUserService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

/**
 * <p>
 *  服务实现类
 * </p>
 *
 * @author flobby
 * @since 2023-05-04
 */
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements IUserService {

}
