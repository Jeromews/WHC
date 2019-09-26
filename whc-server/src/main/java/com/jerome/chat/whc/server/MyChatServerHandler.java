package com.jerome.chat.whc.server;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.util.concurrent.GlobalEventExecutor;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * @author wangsheng
 * @date 2019/9/2
 */
public class MyChatServerHandler extends SimpleChannelInboundHandler<String> {

    private static ChannelGroup channelGroup = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);

    private static final String key = "bodyguardBoysWHC";

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, String msg) throws Exception {
        Channel channel = ctx.channel();
        String name = getName(channel);
        channelGroup.forEach(ch -> {
            try {
                String decrypt = decrypt(msg);
                String encrypt = encrypt(name + ":" + decrypt);
                ch.writeAndFlush(encrypt + "\n");
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
        Channel channel = ctx.channel();
        String name = getName(channel);
        channelGroup.writeAndFlush(encrypt("用户-" + name + "加入聊天室\n"));
        channelGroup.add(channel);
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
        Channel channel = ctx.channel();
        String name = getName(channel);

        channelGroup.writeAndFlush(encrypt("用户-" + name + "离开聊天室\n"));
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        Channel channel = ctx.channel();
        String name = getName(channel);
        System.out.println(name + "上线了");
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        String name = getName(ctx.channel());
        System.out.println(name + "下线了");
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        cause.printStackTrace();
        ctx.close();
    }

    private String getName(Channel channel) {
        String ip = channel.remoteAddress().toString().split(":")[0];
        if (StringUtils.equals(ip, "/10.57.242.209")) {
            return "陈康";
        } else if (StringUtils.equals(ip, "/10.57.241.225")) {
            return "王晟";
        } else if (StringUtils.equals(ip, "/10.57.240.26")) {
            return "郝宗强";
        } else {
            return "未知人物";
        }
    }

    private static String decrypt(String encryptContent) throws Exception {
        byte[] raw = key.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] encrypted = Base64.decodeBase64(encryptContent);
        byte[] original = cipher.doFinal(encrypted);
        return new String(original, StandardCharsets.UTF_8);
    }

    private static String encrypt(String content) throws Exception {

        byte[] raw = key.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] encrypted = cipher.doFinal(content.getBytes(StandardCharsets.UTF_8));

        return Base64.encodeBase64String(encrypted);
    }
}
