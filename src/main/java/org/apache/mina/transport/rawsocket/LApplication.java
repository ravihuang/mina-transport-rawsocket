package org.apache.mina.transport.rawsocket;

import java.nio.ByteBuffer;

import org.jnetpcap.packet.JPacket;

/**
 * 应用层
 * @author Ravi Huang
 *
 */
public class LApplication extends ARawLayer<byte[]>{
    private int id;
    
    public void reinit(int id,byte[] payload) {
        this.id=id;
        this.content = payload;
    }

    @Override
    public byte[] getHeader(JPacket pkt, int id) {
        return content;
    }

    @Override
    public int length() {
       return this.content.length;
    }

    @Override
    public int getType() {
        return id;
    }

    @Override
    public void build(IRawLayer upLayer) {
        //do nothing        
    }
}
