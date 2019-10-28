package com.jerome.chat.whc.client;

import io.netty.channel.*;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * @author wangsheng
 * @date 2019/9/24
 */
public class MyChatClientHandler extends SimpleChannelInboundHandler<String> {

    private static final String key = "bodyguardBoysWHC";

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, String msg) throws Exception {
        System.out.println(decrypt(msg));
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
}
