package com.jerome.chat.whc.server.pojo;

import io.netty.channel.Channel;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * @author wangsheng
 * @date 2019/10/31
 */
@Getter
@Setter
@ToString
public class ChannelInfo {

    //账户名
    private String accountName ="";
    //真实姓名
    private String realName ="";
    //远程地址
    private String remoteAddress="";
    //Channel对象
    private Channel channel;
}
