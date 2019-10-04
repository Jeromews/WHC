package com.jerome.chat.server.handle;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.group.ChannelGroup;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketServerProtocolHandler;

/**
 * @author roll
 * created on 2019-10-03 18:03
 */
public class TextWebSocketFrameHandler extends SimpleChannelInboundHandler<TextWebSocketFrame> {

    private final ChannelGroup group;

    public TextWebSocketFrameHandler(ChannelGroup group) {
        this.group = group;
    }

    /**
     * 处理自定义事件
     */
    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt == WebSocketServerProtocolHandler.ServerHandshakeStateEvent.HANDSHAKE_COMPLETE) {
            // 如果该事件表示握手哼过，则从该ChannelPipeline中移除HttpRequestHandler，因为将不会接受到任何Http消息了
            ctx.pipeline().remove(HttpRequestHandler.class);
            // 通知所有已经链接的WebSocket客户端新的客户端已经连接上了。
            group.writeAndFlush(new TextWebSocketFrame("Client" + ctx.channel() + "joined"));
            // 将新的WebSocket channel天交到ChannelGroup中，以便他能接收到所有的消息。
            group.add(ctx.channel());
        } else {
            super.userEventTriggered(ctx, evt);
        }
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, TextWebSocketFrame msg) throws Exception {
        // 增加消息的引用技术，并将它写到ChannelGroup中所有已经链接的客户端
        group.writeAndFlush(msg.retain());
    }
}
