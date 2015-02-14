package org.apache.mina.transport.rawsocket;

import java.nio.ByteBuffer;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.lan.IEEE802dot1q;

/**
 * vlan层
 * @author Ravi Huang
 *
 */
public class LVlan implements IRawLayer<IEEE802dot1q>{
    private byte cfi;
    private int id;
    private byte priority;
    private int length; //payload+layer
    byte[] bs;

    public LVlan(byte priority, byte cfi, int id) {
        super();
        this.priority = priority;
        this.cfi = cfi;
        this.id = id;
    }
    
    public LVlan(byte priority, byte cfi, int id, boolean uselength) {
        super();
        this.priority = priority;
        this.cfi = cfi;
        this.id = id;        
    }
    
    @Override
    public ByteBuffer encode(ByteBuffer buf) {        
        buf.put(bs);
        return buf;
    }

    public byte getCfi() {
        return cfi;
    }

    public int getId() {
        return id;
    }

    public byte getPriority() {
        return priority;
    }

    public void setCfi(byte cfi) {
        this.cfi = cfi;
    }

    public void setId(int id) {
        this.id = id;
    }

    public void setPriority(byte priority) {
        this.priority = priority;
    }

    @Override
    public IEEE802dot1q getHeader(JPacket pkt,int index) {        
        return pkt.getHeaderByIndex(index, new IEEE802dot1q());
    }

    @Override
    public int length() {
        return length;
    }
    
    @Override
    public int getType() {
        return 0x8100;
    }

    @Override
    public void build(IRawLayer upLayer) {
        if(upLayer==null)
            throw new Error("hasn't payload");
        int type=upLayer.getType();
        if(type<0){            
            type=upLayer.length();
        }
        if(bs==null){
            bs=new byte[4];
            bs[0]=(byte)((priority<<5)+(cfi<<4)+(id>>>8));
            bs[1]=(byte)(id%256);
        }
        bs[2]=(byte)(type>>>8);
        bs[3]=(byte)(type&0xff);
        this.length=4+upLayer.length();
    }

}
