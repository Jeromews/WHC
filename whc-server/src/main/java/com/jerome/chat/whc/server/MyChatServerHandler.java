package com.jerome.chat.whc.server;

import com.jerome.chat.whc.server.pojo.ChannelInfo;
import com.jerome.chat.whc.server.pojo.PrivateChatChannelInfo;
import com.jerome.chat.whc.server.pojo.ReceiveMessage;
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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * @author wangsheng
 * @date 2019/9/2
 */
public class MyChatServerHandler extends SimpleChannelInboundHandler<String> {

    private static ChannelGroup channelGroup = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);

    //remoteAddress——channelInfo
    private static Map<String, ChannelInfo> connectedList = new ConcurrentHashMap<>();

    // accountName——channelInfo
    private static Map<String, ChannelInfo> accountChannelMap = new ConcurrentHashMap<>();

    // private chat accountName——channelInfo
    private static Map<String, PrivateChatChannelInfo> privateChatMap = new ConcurrentHashMap<>();

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
            //解密报文
            String decrypt = decrypt(msg);
            if (StringUtils.isBlank(decrypt)) {
                return;
            }
            String returnMsg;
            if (decrypt.equals("-help")) {
                returnMsg = "登录请输入：-u 账户名 -p 密码 -e \n修改密码请输入：-ch 账户名 -p 原密码 -n 新密码 -e\n" +
                        "注册用户请输入：-ri 账户名 -p 密码 -r 真实姓名 -e（非法姓名，如'陈康的爸爸'等直接后台定期移除账号） \n" +
                        "私聊请输入：-pri 对方账户名 -e \n" +
                        "接到私聊请求后，同意请输入-accept,即可开始私聊，拒绝请输入-refuse。（注：私聊双方将无法看见聊天室信息）\n" +
                        "若想退出私聊，请输入-exitPrivate \n" +
                        "查看当前在线用户请输入：-all";
                channel.writeAndFlush(encrypt(returnMsg) + "\n");
                return;
            }
            ReceiveMessage receiveMessage = getReceiveMessage(decrypt);
            ChannelInfo channelInfo = connectedList.get(channel.remoteAddress().toString());
            //已登录操作
            if (channelInfo != null && StringUtils.isNotBlank(channelInfo.getAccountName())) {
                if (decrypt.length() >= 4) {
                    if (StringUtils.equals(decrypt.substring(0, 3), "-ch")) {
                        if (checkAccount(receiveMessage.getChangeAccountName(), receiveMessage.getOldPassword())) {
                            channel.writeAndFlush(encrypt(changePassword(receiveMessage.getChangeAccountName(), receiveMessage.getNewPassword())) + "\n");
                            return;
                        } else {
                            String checkMsg = "用户名或密码错误，请重试";
                            channel.writeAndFlush(encrypt(checkMsg) + "\n");
                            return;
                        }
                    } else if (StringUtils.equals(decrypt.substring(0, 2), "-u")) {
                        returnMsg = "当前已登录，请勿重复登录";
                        channel.writeAndFlush(encrypt(returnMsg) + "\n");
                        return;
                    } else if (StringUtils.equals(decrypt.substring(0, 3), "-ri")) {
                        returnMsg = registryAccount(receiveMessage.getRegistryAccountName(), receiveMessage.getRegistryPassword(), receiveMessage.getRealName());
                        channel.writeAndFlush(encrypt(returnMsg) + "\n");
                        return;
                    } else if (StringUtils.equals(decrypt, "-all")) {
                        returnMsg = accountChannelMap.entrySet().stream().map(entry -> entry.getKey() + "——" + entry.getValue().getRealName()).collect(Collectors.joining("、"));
                        channel.writeAndFlush(encrypt(returnMsg) + "\n");
                        return;
                    } else if (StringUtils.equals(decrypt.substring(0, 4), "-pri")) {

                        ChannelInfo receiverChannel = accountChannelMap.get(receiveMessage.getPrivateAccount());
                        if (StringUtils.equals(receiverChannel.getAccountName(), channelInfo.getAccountName())) {
                            returnMsg = "和您自己私聊🐎呢?";
                            channel.writeAndFlush(encrypt(returnMsg) + "\n");
                            return;
                        }
                        PrivateChatChannelInfo receiver = privateChatMap.get(channelInfo.getAccountName());
                        PrivateChatChannelInfo initiator = privateChatMap.get(receiverChannel.getAccountName());
                        if (receiver != null) {
                            returnMsg = "您已处在私聊或私聊申请中，请勿重复发起私聊申请";
                            channel.writeAndFlush(encrypt(returnMsg) + "\n");
                            return;
                        }
                        if (initiator != null) {
                            returnMsg = "您申请私聊的对象已处在私聊或私聊申请中，请稍后再试";
                            channel.writeAndFlush(encrypt(returnMsg) + "\n");
                            return;
                        }
                        returnMsg = String.format("用户：%s ,姓名：%s 请求与您进行私聊，同意请输入-accept,拒绝请输入-refuse", channelInfo.getAccountName(), channelInfo.getRealName());
                        receiverChannel.getChannel().writeAndFlush(encrypt(returnMsg) + "\n");
                        PrivateChatChannelInfo privateChatChannelInfo = new PrivateChatChannelInfo();
                        privateChatChannelInfo.setStatus(0);
                        privateChatChannelInfo.setAccountName(channelInfo.getAccountName());
                        privateChatChannelInfo.setChannel(channelInfo.getChannel());
                        PrivateChatChannelInfo targetPrivateChatChannelInfo = new PrivateChatChannelInfo();
                        targetPrivateChatChannelInfo.setStatus(0);
                        targetPrivateChatChannelInfo.setAccountName(receiverChannel.getAccountName());
                        targetPrivateChatChannelInfo.setChannel(receiverChannel.getChannel());
                        privateChatMap.put(channelInfo.getAccountName(), targetPrivateChatChannelInfo);
                        privateChatMap.put(receiverChannel.getAccountName(), privateChatChannelInfo);
                        return;
                    } else if (StringUtils.equals(decrypt, "-accept")) {
                        PrivateChatChannelInfo initiator = privateChatMap.get(channelInfo.getAccountName());
                        if (initiator == null || initiator.getStatus() == 1) {
                            return;
                        } else {
                            PrivateChatChannelInfo receiver = privateChatMap.get(initiator.getAccountName());
                            receiver.setStatus(1);
                            initiator.setStatus(1);
                            returnMsg = "私聊通道已打开。开始畅所欲言吧~";
                            initiator.getChannel().writeAndFlush(encrypt(returnMsg) + "\n");
                            receiver.getChannel().writeAndFlush(encrypt(returnMsg) + "\n");
                            return;
                        }
                    } else if (StringUtils.equals(decrypt, "-refuse")) {
                        PrivateChatChannelInfo initiator = privateChatMap.get(channelInfo.getAccountName());
                        if (initiator == null || initiator.getStatus() == 1) {
                            return;
                        } else {
                            privateChatMap.remove(initiator.getAccountName());
                            privateChatMap.remove(channelInfo.getAccountName());
                            returnMsg = "对方拒绝与您私聊，嘿嘿。";
                            initiator.getChannel().writeAndFlush(encrypt(returnMsg) + "\n");
                            return;
                        }
                    }else if(StringUtils.equals(decrypt,"-exitPrivate")){
                        PrivateChatChannelInfo initiator = privateChatMap.get(channelInfo.getAccountName());
                        if (initiator == null) {
                            return;
                        } else {
                            privateChatMap.remove(initiator.getAccountName());
                            privateChatMap.remove(channelInfo.getAccountName());
                            returnMsg = "已经退出私聊回到聊天室拉。";
                            initiator.getChannel().writeAndFlush(encrypt(returnMsg) + "\n");
                            channelInfo.getChannel().writeAndFlush(encrypt("对方取消了私聊"+returnMsg) + "\n");
                            return;
                        }
                    }
                }
                PrivateChatChannelInfo initiator = privateChatMap.get(channelInfo.getAccountName());
                if (initiator != null) {
                    PrivateChatChannelInfo receiver = privateChatMap.get(initiator.getAccountName());
                    if (initiator.getStatus() == 1 && receiver != null && receiver.getStatus() == 1) {
                        StringBuilder stringBuilder = new StringBuilder();
                        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                        String encrypt = encrypt(stringBuilder.append(df.format(new Date())).append(" ").append(channelInfo.getRealName()).append(":").append(decrypt).toString());
                        initiator.getChannel().writeAndFlush(encrypt + "\n");
                        receiver.getChannel().writeAndFlush(encrypt + "\n");
                        return;
                    }
                }

                channelGroup.forEach(ch -> {
                    Collection<PrivateChatChannelInfo> values = privateChatMap.values();
                    for (PrivateChatChannelInfo privateChatChannelInfo : values) {
                        if (ch.equals(privateChatChannelInfo.getChannel()) && privateChatChannelInfo.getStatus() == 1) {
                            return;
                        }
                    }
                    try {
                        StringBuilder stringBuilder = new StringBuilder();
                        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                        String encrypt = encrypt(stringBuilder.append(df.format(new Date())).append(" ").append(channelInfo.getRealName()).append(":").append(decrypt).toString());
                        ch.writeAndFlush(encrypt + "\n");
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });

            }
            //未登录操作
            else {
                String checkMsg = "";
                if (decrypt.length() < 2) {
                    return;
                }
                if (StringUtils.equals(decrypt.substring(0, 2), "-u") && (StringUtils.isBlank(receiveMessage.getLoginAccountName()) || StringUtils.isBlank(receiveMessage.getPassword()))) {
                    channel.writeAndFlush(encrypt("请输入正确的用户名密码") + "\n");
                    return;
                } else if (StringUtils.equals(decrypt.substring(0, 3), "-ch") && (StringUtils.isBlank(receiveMessage.getChangeAccountName()) || StringUtils.isBlank(receiveMessage.getOldPassword()))) {
                    channel.writeAndFlush(encrypt("请输入正确的用户名密码") + "\n");
                    return;
                }
                if (StringUtils.equals(decrypt.substring(0, 3), "-ch")) {
                    if (checkAccount(receiveMessage.getChangeAccountName(), receiveMessage.getOldPassword())) {
                        checkMsg = changePassword(receiveMessage.getChangeAccountName(), receiveMessage.getNewPassword());
                    } else {
                        checkMsg = "用户名或密码错误，请重试";
                    }
                } else if (StringUtils.equals(decrypt.substring(0, 2), "-u")) {
                    if (checkAccount(receiveMessage.getLoginAccountName(), receiveMessage.getPassword())) {
                        checkMsg = "登录成功";
                        ChannelInfo curChannelInfo = new ChannelInfo();
                        curChannelInfo.setAccountName(receiveMessage.getLoginAccountName());
                        curChannelInfo.setRealName(getName(receiveMessage.getLoginAccountName()));
                        curChannelInfo.setRemoteAddress(channel.remoteAddress().toString());
                        curChannelInfo.setChannel(channel);
                        connectedList.put(channel.remoteAddress().toString(), curChannelInfo);
                        accountChannelMap.put(curChannelInfo.getAccountName(), curChannelInfo);
                    } else {
                        checkMsg = "用户名或密码错误，请重试";
                    }
                } else if (StringUtils.equals(decrypt.substring(0, 3), "-ri")) {
                    returnMsg = registryAccount(receiveMessage.getRegistryAccountName(), receiveMessage.getRegistryPassword(), receiveMessage.getRealName());
                    channel.writeAndFlush(encrypt(returnMsg) + "\n");
                    return;
                }
                channel.writeAndFlush(encrypt(checkMsg) + "\n");

            }
        } catch (Exception e) {
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

    /**
     * 组装接收信息对象
     *
     * @param message 接收信息
     * @return 信息对象
     */
    private ReceiveMessage getReceiveMessage(String message) {

        //登录用户名
        Pattern p1 = Pattern.compile("-u (\\w+) -p");
        //登录密码
        Pattern p2 = Pattern.compile("-p (\\w+) -e");
        //修改密码时用户名
        Pattern p3 = Pattern.compile("-ch (\\w+) -p");
        //修改密码时老密码
        Pattern p4 = Pattern.compile("-p (\\w+) -n");
        //修改密码时新密码
        Pattern p5 = Pattern.compile("-n (\\w+) -e");
        //注册用户名
        Pattern p6 = Pattern.compile("-ri (\\w+) -p");
        //注册真是姓名
        Pattern p7 = Pattern.compile(".{3}-r (.*) -e");
        //注册密码
        Pattern p8 = Pattern.compile("-p (\\w+) -r");
        //私聊对象用户名
        Pattern p9 = Pattern.compile("-pri (\\w+) -e");
        Matcher m1 = p1.matcher(message);
        Matcher m2 = p2.matcher(message);
        Matcher m3 = p3.matcher(message);
        Matcher m4 = p4.matcher(message);
        Matcher m5 = p5.matcher(message);
        Matcher m6 = p6.matcher(message);
        Matcher m7 = p7.matcher(message);
        Matcher m8 = p8.matcher(message);
        Matcher m9 = p9.matcher(message);
        ReceiveMessage receiveMessage = new ReceiveMessage();
        while (m1.find()) {
            receiveMessage.setLoginAccountName(m1.group(1));
        }
        while (m2.find()) {
            receiveMessage.setPassword(m2.group(1));
        }
        while (m3.find()) {
            receiveMessage.setChangeAccountName(m3.group(1));
        }
        while (m4.find()) {
            receiveMessage.setOldPassword(m4.group(1));
        }
        while (m5.find()) {
            receiveMessage.setNewPassword(m5.group(1));
        }
        while (m6.find()) {
            receiveMessage.setRegistryAccountName(m6.group(1));
        }
        while (m7.find()) {
            receiveMessage.setRealName(m7.group(1));
        }
        while (m8.find()) {
            receiveMessage.setRegistryPassword(m8.group(1));
        }
        while (m9.find()) {
            receiveMessage.setPrivateAccount(m9.group(1));
        }
        return receiveMessage;
    }
}
