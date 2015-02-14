package org.apache.mina.transport.rawsocket;

import java.nio.ByteBuffer;

import org.jnetpcap.packet.JPacket;

public interface IRawLayer<T> {
    /**
     * 打包
     * @param buf
     * @return
     */
    ByteBuffer encode(ByteBuffer buf);
    
    /**
     * 获得该层数据
     * @param pkt
     * @param id
     * @return
     */    
    T getHeader(JPacket pkt,int id);
    
    /**
     * 该层及该层payload总长度
     * @return
     */
    int length();
    
    /**
     * 该层类型
     * @return
     */
    int getType();
    
    /**
     * build该层内容
     * @param upLayer
     */
    void build(IRawLayer upLayer);
}
