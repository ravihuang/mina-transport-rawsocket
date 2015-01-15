package org.apache.mina.transport.rawsocket;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RawPacket {
    private static byte[] BC_ADDR=new byte[]{(byte)0xff,(byte)0xff,(byte)0xff,
                                             (byte)0xff,(byte)0xff,(byte)0xff};
    private static Logger log = LoggerFactory.getLogger(RawPacket.class);
    
    /** The tcppacket. */
    private static JPacket tcppacket = new JMemoryPacket(JProtocol.ETHERNET_ID,
            " 001801bf 6adc0025 4bb7afec 08004500 "
                    + " 0041a983 40004006 d69ac0a8 00342f8c "
                    + " ca30c3ef 008f2e80 11f52ea8 4b578018 "
                    + " ffffa6ea 00000101 080a152e ef03002a "
                    + " 2c943538 322e3430 204e4f4f 500d0a");

    /**
     * Create_eth_packet.
     *
     * @param dmac
     *            the dmac
     * @param smac
     *            the smac
     * @param type
     *            the type
     * @param payload
     *            the payload
     * @return the j packet
     */
    public static JPacket create_eth_packet(byte[] dmac, byte[] smac, int type,
            byte[] payload) {
        ByteBuffer buf = ByteBuffer.allocate(14 + payload.length);
        buf.put(dmac).put(smac).putShort((short) type).put(payload);

        JPacket pkt = new JMemoryPacket(JProtocol.ETHERNET_ID, buf.array());
        return pkt;

    }

    /**
     * Create_tcp_packet.
     *
     * @param sourceIP
     *            the source ip
     * @param sourcePort
     *            the source port
     * @param destIP
     *            the dest ip
     * @param destPort
     *            the dest port
     * @param payload
     *            the payload
     * @return the j packet
     */
    public static JPacket create_tcp_packet(int sourceIP, int sourcePort,
            int destIP, int destPort, byte[] payload) {
        tcppacket.getHeader(new Ip4());
        Tcp tcp = tcppacket.getHeader(new Tcp());
        tcp.source(sourcePort);
        tcp.destination(destPort);

        int payloadStartOffset = tcp.getGapOffset();

        ByteBuffer buf = ByteBuffer.allocate(payloadStartOffset
                + payload.length);

        byte[] bytes = buf.array();

        for (int i = payloadStartOffset; i < payloadStartOffset
                + payload.length; ++i)
            bytes[i] = payload[i - payloadStartOffset];

        tcppacket.transferFrom(bytes);

        return tcppacket;
    }

    public static RawPacket match_local(PcapPacket packet, EthAddress localAddr,
            boolean broadcast,boolean groupcast) {
        RawPacket tmp = new RawPacket(packet, localAddr.getFrameType());
        if(localAddr.getEthType() != tmp.eth().type())
            return null;
        
        if (Arrays.equals(localAddr.mac(), tmp.eth().destination())) {
            return tmp;
        }
        
        if(broadcast&&(Arrays.equals(BC_ADDR, tmp.eth().destination()))){
            tmp.isBroadcast=true;
            return tmp;
        }
        
        if(groupcast&&(tmp.eth().destination()[0]%2==1)){
            tmp.isGroupcast=true;
            return tmp;
        }
        
        return null;
    }

    /** The eth. */
    private Ethernet eth;

    /** The ipv4. */
    private Ip4 ipv4;

    /** The ipv6. */
    private Ip6 ipv6;

    private boolean isBroadcast=false;

    private boolean isGroupcast=false;
    
    /** The lastheader. */
    private JHeader lastheader;
    /** The packet. */
    private JPacket packet;
    
    /** The tcp. */
    private Tcp tcp;

    /** The udp. */
    private Udp udp;

    /**
     * Instantiates a new raw packet.
     *
     * @param packet
     *            the packet
     * @param protocol
     *            the protocol
     */
    public RawPacket(JPacket packet, int protocol) {
        this.packet = packet;
        // packet.scan(JProtocol.ETHERNET_ID);
        packet.scan(protocol);
    }

    /**
     * Eth.
     *
     * @return the ethernet
     */
    public Ethernet eth() {
        if (eth != null)
            return eth;

        eth = packet.getHeader(new Ethernet());
        lastheader = eth;
        return eth;
    }

    /**
     * Ipv4.
     *
     * @return the ip4
     */
    public Ip4 ipv4() {
        if (ipv4 != null)
            return ipv4;
        ipv4 = packet.getHeader(new Ip4());
        lastheader = ipv4;
        return ipv4;
    }

    /**
     * Ipv6.
     *
     * @return the ip6
     */
    public Ip6 ipv6() {
        if (ipv6 != null)
            return ipv6;
        ipv6 = packet.getHeader(new Ip6());
        lastheader = ipv6;
        return ipv6;
    }

    public boolean isBroadcast() {
        return isBroadcast;
    }

    public boolean isGroupcast() {
        return isGroupcast;
    }

    /**
     * Payload.
     *
     * @return the byte[]
     */
    public byte[] payload() {
        return lastheader.getPayload();
    }

    /**
     * Tcp.
     *
     * @return the tcp
     */
    public Tcp tcp() {
        if (tcp != null)
            return tcp;

        tcp = packet.getHeader(new Tcp());
        lastheader = tcp;
        return tcp;
    }

    /**
     * To bytes.
     *
     * @return the byte[]
     */
    public byte[] toBytes() {
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return packet.toString();
    }

    /**
     * Udp.
     *
     * @return the udp
     */
    public Udp udp() {
        if (udp != null)
            return udp;

        udp = packet.getHeader(new Udp());
        lastheader = udp;
        return udp;
    }
}
