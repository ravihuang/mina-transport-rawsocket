package org.apache.mina.transport.rawsocket;

import org.jnetpcap.packet.PcapPacket;

public interface IRawFilter {
    /**
     * RawSelector中用来过滤收到的包，判断是否是所需要的
     * @param packet
     * @return
     * @see RawSelector#match(PcapPacket)
     * @see RawIoPoll#nextPacket(PcapPacket, Object)
     */
    RawPacket filter(PcapPacket packet);
    void keepBroadcastPacket(boolean b);
    void keepGroupcastPacket(boolean b);
}
