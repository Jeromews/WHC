package com.jerome.chat.whc.server.pojo;

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
public class PrivateChatChannelInfo extends ChannelInfo {

    //私聊状态，0发起邀请，1接收邀请。
    private int status;
}
