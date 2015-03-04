package org.apache.mina.transport.rawsocket;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.spi.AbstractSelectableChannel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PeeringException;
import org.jnetpcap.protocol.JProtocol;
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

    private List<IRawLayer> allLayers = new ArrayList();

    byte[] header;

    ByteBuffer buf = ByteBuffer.allocate(RawIoPoll.MTU);

    private LApplication appLayer = new LApplication();

    /**
     * Instantiates a new raw io channel.
     *
     * @param selector
     *            the selector
     */
    protected RawIoChannel(RawSelector selector, List<IRawLayer> layers) {
        super(null);
        this.selector = selector;

        this.allLayers.addAll(layers);
        // add application layer
        this.allLayers.add(appLayer);
    }

    public RawIoChannel connect(SocketAddress remote) {
        this.remoteAddress = (EthAddress) remote;
        return this;
    }

    /**
     * 判断收到的包是不是当前session需要处理的，一般应该按照ethernet层的信息来过滤. selector会调用
     *
     * @param packet
     *            the packet
     * @return true, if successful
     */
    public boolean filter(RawPacket packet) {
        boolean rst = true;

        if (remoteAddress != null
                && !Arrays.equals(remoteAddress.mac(), packet.eth().source())) {
            rst = false;
        }

        if (DefaultRawSessionConfig.verbose)
            log.debug("{} match:{} lcl={} {}", this, rst, localAddress, packet);
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
        RawPacket pkt = receive(dst);
        if (pkt == null)
            return -1;
        return pkt.getLastHeader().getPayloadLength();
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
        JHeader lastHeader = null;
        if (this.allLayers.size() > 1) {
            int last = allLayers.size() - 2;
            lastHeader = (JHeader) allLayers.get(last).getHeader(
                    pkt.getJPacket(), last + 1);
        } else {
            lastHeader = pkt.eth();
        }

        dst.put(lastHeader.getPayload());
        pkt.setLastHeader(lastHeader);
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

    /**
     * 不处理分片，也就是说如果bs内容超过MTU可能会出错
     * 
     * @param bs
     * @param dstAddr
     * @return
     * @throws IOException
     */
    public int write(byte[] bs, byte[] dstAddr) throws IOException {
        synchronized (buf) {
            buf.rewind();

            // process every layer
            appLayer.reinit(localAddress.getEthType(), bs);
            IRawLayer lastlayer = null;
            for (int i = this.allLayers.size() - 1; i >= 0; i--) {
                this.allLayers.get(i).build(lastlayer);
                lastlayer = this.allLayers.get(i);
            }

            // put ethernet header
            buf.put(dstAddr).put(localAddress.mac())
                    .putShort((short) lastlayer.getType());

            for (IRawLayer tun : this.allLayers) {
                tun.encode(buf);
            }

            if (buf.position() < RawIoPoll.MITU)
                buf.put(new byte[RawIoPoll.MITU - buf.position()]);

            buf.flip();

            JPacket pkt = null;
            try {
                pkt = new JMemoryPacket(JProtocol.ETHERNET_ID, buf);
            } catch (PeeringException e) {
                e.printStackTrace();
            }

            if (selector.write(pkt) == 0) {
                if (DefaultRawSessionConfig.verbose)
                    log.debug("{} send ok {}", localAddress, pkt);
                return bs.length;
            } else {
                if (DefaultRawSessionConfig.verbose)
                    log.debug("{} send fail {}", localAddress, pkt);
                return -1;
            }
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.nio.channels.WritableByteChannel#write(java.nio.ByteBuffer)
     */
    public int write(ByteBuffer src) throws IOException {
        return write(src.array(), remoteAddress.mac());
    }

    public int write(ByteBuffer src, SocketAddress remoteAddress)
            throws IOException {
        return write(src.array(), ((EthAddress) remoteAddress).mac());
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
