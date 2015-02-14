package org.apache.mina.transport.rawsocket;

import java.nio.ByteBuffer;

import org.jnetpcap.packet.JPacket;

/**
 * 应用层
 * @author Ravi Huang
 *
 */
public class LApplication implements IRawLayer<byte[]>{
    private int id;
    private byte[] payload;
    
    public void reinit(int id,byte[] payload) {
        this.id=id;
        this.payload = payload;
    }

    @Override
    public ByteBuffer encode(ByteBuffer buf) {
        buf.put(this.payload);
        return buf;
    }

    @Override
    public byte[] getHeader(JPacket pkt, int id) {
        return payload;
    }

    @Override
    public int length() {
       return this.payload.length;
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
