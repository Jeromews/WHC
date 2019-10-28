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
import java.io.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author wangsheng
 * @date 2019/9/2
 */
public class MyChatServerHandler extends SimpleChannelInboundHandler<String> {

    private static ChannelGroup channelGroup = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);

    private static Map<String, String> connectedList = new ConcurrentHashMap<>();

    private static final String key = "bodyguardBoysWHC";
    private static String filePath;

    static {
        try {
            String name = InetAddress.getLocalHost().getHostName();
            if (StringUtils.equals(name, "wangshengdeMacBook-Air.local")) {
                filePath = "/Users/wangsheng/Documents/IdeaProjects/whc/whc-server/src/main/resources/user.properties";
            } else {
                filePath = "/home/admin/whc/user.properties";
            }
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, String msg) throws Exception {
        Channel channel = ctx.channel();
        try {
            String decrypt = decrypt(msg);
            if (decrypt.equals("-help")) {
                String returnMsg = "登录请输入：-u 账户名 -p 密码 -e \n修改密码请输入：-ch 账户名 -p 原密码 -n 新密码 -e\n" +
                        "注册用户请输入：-ri 账户名 -p 密码 -r 真实姓名（非法姓名，如'陈康的爸爸'等直接后台定期移除账号） -e";
                channel.writeAndFlush(encrypt(returnMsg) + "\n");
                return;
            }
            Pattern p1 = Pattern.compile("-u (\\w+) -p");
            Pattern p2 = Pattern.compile("-p (\\w+) -e");
            Pattern p3 = Pattern.compile("-ch (\\w+) -p");
            Pattern p4 = Pattern.compile("-p (\\w+) -n");
            Pattern p5 = Pattern.compile("-n (\\w+) -e");
            Pattern p6 = Pattern.compile("-ri (\\w+) -p");
            Pattern p7 = Pattern.compile(".{3}-r (.*) -e");
            Pattern p8 = Pattern.compile("-p (\\w+) -r");
            Matcher m1 = p1.matcher(decrypt);
            Matcher m2 = p2.matcher(decrypt);
            Matcher m3 = p3.matcher(decrypt);
            Matcher m4 = p4.matcher(decrypt);
            Matcher m5 = p5.matcher(decrypt);
            Matcher m6 = p6.matcher(decrypt);
            Matcher m7 = p7.matcher(decrypt);
            Matcher m8 = p8.matcher(decrypt);
            String loginAccountName = "";
            String password = "";
            String changeAccountName = "";
            String oldPassword = "";
            String newPassword = "";
            String registryAccountName = "";
            String realName = "";
            String registryPassword = "";
            while (m1.find()) {
                loginAccountName = m1.group(1);
            }
            while (m2.find()) {
                password = m2.group(1);
            }
            while (m3.find()) {
                changeAccountName = m3.group(1);
            }
            while (m4.find()) {
                oldPassword = m4.group(1);
            }
            while (m5.find()) {
                newPassword = m5.group(1);
            }
            while (m6.find()) {
                registryAccountName = m6.group(1);
            }
            while (m7.find()) {
                realName = m7.group(1);
            }
            while (m8.find()) {
                registryPassword = m8.group(1);
            }
            String accountName = connectedList.get(channel.remoteAddress().toString());
            if (StringUtils.isNotBlank(accountName)) {
                if (decrypt.length() >= 3) {
                    if (StringUtils.equals(decrypt.substring(0, 3), "-ch")) {
                        if (checkAccount(changeAccountName, oldPassword)) {
                            channel.writeAndFlush(encrypt(changePassword(changeAccountName, newPassword)) + "\n");
                            return;
                        } else {
                            String checkMsg = "用户名或密码错误，请重试";
                            channel.writeAndFlush(encrypt(checkMsg) + "\n");
                            return;
                        }
                    } else if (StringUtils.equals(decrypt.substring(0, 2), "-u")) {
                        String returnMsg = "当前已登录，请勿重复登录";
                        channel.writeAndFlush(encrypt(returnMsg) + "\n");
                        return;
                    } else if (StringUtils.equals(decrypt.substring(0, 3), "-ri")) {
                        String returnMsg = registryAccount(registryAccountName, registryPassword, realName);
                        channel.writeAndFlush(encrypt(returnMsg) + "\n");
                        return;
                    }
                }
                String name = getName(accountName);
                StringBuilder stringBuilder = new StringBuilder();
                channelGroup.forEach(ch -> {
                    try {
                        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                        String encrypt = encrypt(stringBuilder.append(df.format(new Date())).append(" ").append(name).append(":").append(decrypt).toString());
                        ch.writeAndFlush(encrypt + "\n");
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });

            } else {

                String checkMsg = "";
                if (decrypt.length() < 2) {
                    return;
                }
                if (StringUtils.equals(decrypt.substring(0, 2), "-u") && (StringUtils.isBlank(loginAccountName) || StringUtils.isBlank(password))) {
                    channel.writeAndFlush(encrypt("请输入正确的用户名密码") + "\n");
                    return;
                } else if (StringUtils.equals(decrypt.substring(0, 3), "-ch") && (StringUtils.isBlank(changeAccountName) || StringUtils.isBlank(oldPassword))) {
                    channel.writeAndFlush(encrypt("请输入正确的用户名密码") + "\n");
                    return;
                }
                if (StringUtils.equals(decrypt.substring(0, 3), "-ch")) {
                    if (checkAccount(changeAccountName, oldPassword)) {
                        checkMsg = changePassword(changeAccountName, newPassword);
                    } else {
                        checkMsg = "用户名或密码错误，请重试";
                    }
                } else if (StringUtils.equals(decrypt.substring(0, 2), "-u")) {
                    if (checkAccount(loginAccountName, password)) {
                        checkMsg = "登录成功";
                        connectedList.put(channel.remoteAddress().toString(), loginAccountName);
                    } else {
                        checkMsg = "用户名或密码错误，请重试";
                    }
                } else if (StringUtils.equals(decrypt.substring(0, 3), "-ri")) {
                    String returnMsg = registryAccount(registryAccountName, registryPassword, realName);
                    channel.writeAndFlush(encrypt(returnMsg) + "\n");
                    return;
                }
                channel.writeAndFlush(encrypt(checkMsg) + "\n");

            }
        }catch(Exception e){
            channel.writeAndFlush(encrypt("未知错误") + "\n");
        }
    }


    @Override
    public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
        Channel channel = ctx.channel();
        //String accountName = connectedList.get(channel.remoteAddress().toString());
        //String name = getName(accountName);
        //channelGroup.writeAndFlush(encrypt("用户-" + name + "加入聊天室\n"));
        channelGroup.add(channel);
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
        Channel channel = ctx.channel();
//        String accountName = connectedList.get(channel.remoteAddress().toString());
//        String name = getName(accountName);
        channelGroup.remove(channel);
        //channelGroup.writeAndFlush(encrypt("用户-" + name + "离开聊天室\n"));
    }

//    @Override
//    public void channelActive(ChannelHandlerContext ctx) throws Exception {
//        Channel channel = ctx.channel();
//        String accountName = connectedList.get(channel.remoteAddress().toString());
//        String name = getName(accountName);
//        System.out.println(name + "上线了");
//    }
//
//    @Override
//    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
//        String accountName = connectedList.get(ctx.channel().remoteAddress().toString());
//        String name = getName(accountName);
//        System.out.println(name + "下线了");
//    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        ctx.close();
    }

    private String getName(String accountName) throws Exception {

        Properties properties = new Properties();
        FileInputStream fileInputStream = new FileInputStream(filePath);
        InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream, StandardCharsets.UTF_8);
        properties.load(inputStreamReader);
        return (String) properties.get(accountName + ".name");
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

    private String registryAccount(String registryAccountName, String password, String realName) throws Exception {
        if (StringUtils.isBlank(registryAccountName) || StringUtils.isBlank(password) || StringUtils.isBlank(realName)) {
            return "请输入正确的指令及信息！";
        }
        Properties properties = new Properties();
        FileInputStream fileInputStream = new FileInputStream(filePath);
        InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream, StandardCharsets.UTF_8);
        properties.load(inputStreamReader);
        if (StringUtils.isNotBlank((String) properties.get(registryAccountName + ".name"))) {
            return "账户名已存在，请更换注册！";
        } else {
            properties.setProperty(registryAccountName + ".password", password);
            properties.setProperty(registryAccountName + ".name", realName);
            FileOutputStream oFile;
            oFile = new FileOutputStream(filePath);
            //将Properties中的属性列表（键和元素对）写入输出流
            properties.store(oFile, "");
            oFile.close();
            return "注册成功！";
        }
    }

    private boolean checkAccount(String accountName, String password) throws Exception {
        Properties properties = new Properties();
        FileInputStream fileInputStream = new FileInputStream(filePath);
        InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream, StandardCharsets.UTF_8);
        properties.load(inputStreamReader);

        String curPassword = (String) properties.get(accountName + ".password");
        if (StringUtils.isNotBlank(curPassword)) {
            return StringUtils.equals(curPassword, password);
        } else {
            return false;
        }
    }

    private String changePassword(String changeAccountName, String newPassword) throws Exception {
        Properties properties = new Properties();
        FileInputStream fileInputStream = new FileInputStream(filePath);
        InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream, StandardCharsets.UTF_8);
        properties.load(inputStreamReader);
        properties.setProperty(changeAccountName + ".password", newPassword);
        FileOutputStream oFile;
        oFile = new FileOutputStream(filePath);
        //将Properties中的属性列表（键和元素对）写入输出流
        properties.store(oFile, "");
        oFile.close();
        return "修改成功";
    }
}
