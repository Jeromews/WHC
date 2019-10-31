package com.jerome.chat.whc.server.pojo;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serializable;

/**
 * @author wangsheng
 * @date 2019/10/31
 */
@Getter
@Setter
@ToString

public class ReceiveMessage implements Serializable {

    private static final long serialVersionUID = 6124015288710092350L;

    //登录账户名
    private String loginAccountName = "";

    //登录密码
    private String password = "";

    //修改密码账户名
    private String changeAccountName = "";

    //旧密码
    private String oldPassword = "";

    //新密码
    private String newPassword = "";

    //注册账户名
    private String registryAccountName = "";

    //真实姓名
    private String realName = "";

    //注册密码
    private String registryPassword = "";

    //私聊账户
    private String privateAccount = "";

}
