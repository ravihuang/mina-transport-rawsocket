package org.apache.mina.transport.rawsocket;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.spi.AbstractSelectableChannel;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Queue;

import org.jnetpcap.packet.JPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RawIoChannel extends AbstractSelectableChannel implements
        ByteChannel {

    /** The log. */
    protected static Logger log = LoggerFactory.getLogger(RawIoChannel.class);

    /** The config. */
    DefaultRawSessionConfig config;

    /** The fifo. */
    private Queue<RawPacket> fifo = new LinkedList<RawPacket>();

    /** The local. */
    private EthAddress localAddress;

    /** The remote. */
    private EthAddress remoteAddress;

    /** The selector. */
    private RawSelector selector;

    /**
     * Instantiates a new raw io channel.
     *
     * @param selector
     *            the selector
     */
    protected RawIoChannel(RawSelector selector) {
        super(null);
        this.selector = selector;       
    }
    
    public RawIoChannel connect(SocketAddress remote){
        this.remoteAddress=(EthAddress)remote;
        return this;
    }
    
    /**
     * 判断收到的包是不是当前session需要处理的，一般应该按照ethernet层的信息来过滤.
     * selector会调用
     *
     * @param packet
     *            the packet
     * @return true, if successful
     */
    public boolean filter(RawPacket packet) {
        boolean rst = true;
        
        if (remoteAddress!=null&&!Arrays.equals(remoteAddress.mac(), packet.eth().source())) {
            rst = false;
        }
        
        if (EthAddress.verbose)
            log.debug("{} match:{} lcl={} {}", get_selector(), rst,
                    localAddress, packet);
        return rst;
    }

    /**
     * Gets the _selector.
     *
     * @return the _selector
     */
    public RawSelector get_selector() {
        return this.selector;
    }

    public EthAddress getLocalAddress() {
        return localAddress;
    }

    /**
     * Checks if is connected.
     *
     * @return true, if is connected
     */
    public boolean isConnected() {
        return selector.is_started();
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.nio.channels.ReadableByteChannel#read(java.nio.ByteBuffer)
     */
    public int read(ByteBuffer dst) throws IOException {
        if (!fifo.isEmpty()) {
            RawPacket pkt = fifo.remove();
            dst.put(pkt.payload());
            return pkt.payload().length;
        }
        return -1;
    }

    /**
     * Receive.
     *
     * @param dst
     *            read payload
     * @return 远端地址，目前只支持mac
     */
    public RawPacket receive(ByteBuffer dst) {
        if (fifo.isEmpty())
            return null;
        RawPacket pkt = fifo.remove();
        dst.put(pkt.payload());
        return pkt;

    }

    public void setLocalAddress(EthAddress localAddress) {
        this.localAddress = localAddress;
    }
    
    public EthAddress getRemoteAddress() {
        return remoteAddress;
    }

    /**
     * Translate and set interest ops.
     *
     * @param ops
     *            the ops
     * @param sk
     *            the sk
     */
    public void translateAndSetInterestOps(int ops, RawSelectionKey sk) {
        // do nothing

    }

    /**
     * Translate and set ready ops.
     *
     * @param ops
     *            the ops
     * @param sk
     *            the sk
     * @return true, if successful
     */
    public boolean translateAndSetReadyOps(int ops, RawSelectionKey sk) {
        // //do nothing
        // sk.nioReadyOps(ops);
        return true;
    }

    /**
     * Translate and update ready ops.
     *
     * @param arg0
     *            the arg0
     * @param arg1
     *            the arg1
     * @return true, if successful
     */
    public boolean translateAndUpdateReadyOps(int arg0, RawSelectionKey arg1) {
        // do nothing
        // System.out.print("todo translateAndUpdateReadyOps");
        return true;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.nio.channels.SelectableChannel#validOps()
     */
    @Override
    public int validOps() {
        return (SelectionKey.OP_READ | SelectionKey.OP_WRITE);
    }

    public int write(byte[] bs,byte[] dstAddr) throws IOException {
        JPacket pkt = RawPacket.create_eth_packet(dstAddr,
                localAddress.mac(), this.localAddress.getEthType(), bs);

        int len = -1;
        if (selector.write(pkt) == 0)
            len = bs.length;
        
        if (EthAddress.verbose)
            log.debug("{} send {}", selector, pkt);
        
        return len;
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see java.nio.channels.WritableByteChannel#write(java.nio.ByteBuffer)
     */
    public int write(ByteBuffer src) throws IOException {
        return write(src.array(), remoteAddress.mac());        
    }
    
    public int write(ByteBuffer src, SocketAddress remoteAddress) throws IOException {
        return write(src.array(), ((EthAddress)remoteAddress).mac());        
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see
     * java.nio.channels.spi.AbstractSelectableChannel#implCloseSelectableChannel
     * ()
     */
    @Override
    protected void implCloseSelectableChannel() throws IOException {
        if (selector.isOpen())
            selector.close();

    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * java.nio.channels.spi.AbstractSelectableChannel#implConfigureBlocking
     * (boolean)
     */
    @Override
    protected void implConfigureBlocking(boolean block) throws IOException {
        // TODO

    }

    /**
     * Adds the.
     *
     * @param pkt
     *            the pkt
     */
    void add(RawPacket pkt) {
        fifo.add(pkt);
    }
}
