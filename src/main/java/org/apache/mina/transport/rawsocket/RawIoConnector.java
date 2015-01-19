package org.apache.mina.transport.rawsocket;

import java.net.SocketAddress;
import java.nio.channels.SelectionKey;
import java.util.Collections;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.Executors;

import org.apache.mina.core.polling.AbstractPollingIoConnector;
import org.apache.mina.core.service.IoProcessor;
import org.apache.mina.core.service.TransportMetadata;
import org.apache.mina.core.session.IoSessionConfig;
import org.jnetpcap.packet.PcapPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RawIoConnector extends
        AbstractPollingIoConnector<RawIoSession, RawIoChannel> implements
        IRawFilter {
    private static Logger log = LoggerFactory.getLogger(RawIoConnector.class);
    private boolean broadcast = false;

    private boolean groupcast = false;

    private EthAddress localAddr;

    /** The selector. */
    private RawSelector selector;

    /** The session. */
    private RawIoSession session;

    public RawIoConnector() {
        this(new DefaultRawSessionConfig(),new RawProcessor(Executors.newCachedThreadPool()));
    }
    
    public RawIoConnector(DefaultRawSessionConfig config) {
        this(config,new RawProcessor(Executors.newCachedThreadPool()));        
    }
    
    public RawIoConnector(RawProcessor processor) {
        this(new DefaultRawSessionConfig(),processor);        
    }
    
    /**
     * Instantiates a new raw io connector.
     *
     * @param config
     *            the config
     * @param processor
     *            the processor
     */
    public RawIoConnector(DefaultRawSessionConfig config, RawProcessor processor) {
        super(config, processor);
        processor.setSelector(selector);
        localAddr=config.getLocalBindingAddr();
    }

    /**
     * Creates a new instance.
     *
     * @param processorCount
     *            the processor count
     */
    public RawIoConnector(int processorCount) {
        super(new DefaultRawSessionConfig(), RawProcessor.class, processorCount);
    }

    /**
     * Creates a new instance.
     *
     * @param processor
     *            the processor
     */
    public RawIoConnector(IoProcessor<RawIoSession> processor) {
        super(new DefaultRawSessionConfig(), processor);
    }
    
    public boolean direct_write(byte[] bs){
        return selector.write(bs)==0;
    }
    
    public RawPacket filter(PcapPacket packet) {
        RawPacket pkt = RawPacket.match_local(packet, localAddr, broadcast,
                this.groupcast);
        if (EthAddress.verbose)
            log.debug("{} match:{} lcl={} {}", selector, pkt != null,
                    localAddr, packet);
        return pkt;
    }

    /**
     * Gets the _session_config.
     *
     * @return the _session_config
     */
    public DefaultRawSessionConfig get_session_config() {
        return (DefaultRawSessionConfig) sessionConfig;
    }

    public EthAddress getLocalAddr() {
        return localAddr;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.service.IoService#getSessionConfig()
     */
    public IoSessionConfig getSessionConfig() {
        return this.sessionConfig;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.service.IoService#getTransportMetadata()
     */
    public TransportMetadata getTransportMetadata() {
        return RawIoSession.METADATA;
    }

    /**
     * Checks if is connected.
     *
     * @return true, if is connected
     */
    public boolean isConnected() {
        return this.selector != null && this.selector.is_started();
    }

    public void keepBroadcastPacket(boolean b) {
        broadcast = b;
    }

    public void keepGroupcastPacket(boolean groupcast) {
        this.groupcast = groupcast;
    }


    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.polling.AbstractPollingIoConnector#allHandles()
     */
    @Override
    protected Iterator<RawIoChannel> allHandles() {
        return Collections.EMPTY_LIST.iterator();
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoConnector#close(java.lang
     * .Object)
     */
    @Override
    protected void close(RawIoChannel handle) throws Exception {
        handle.close();
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoConnector#connect(java.
     * lang.Object, java.net.SocketAddress)
     */
    @Override
    protected boolean connect(RawIoChannel handle, SocketAddress remoteAddress)
            throws Exception {
        if (session != null) {
            throw new Error("already connected");
        }
        handle.connect(remoteAddress);
        return true;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.polling.AbstractPollingIoConnector#destroy()
     */
    @Override
    protected void destroy() throws Exception {
        if (selector != null) {
            selector.close();
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoConnector#finishConnect
     * (java.lang.Object)
     */
    @Override
    protected boolean finishConnect(RawIoChannel handle) throws Exception {
        throw new UnsupportedOperationException();
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoConnector#getConnectionRequest
     * (H)
     */
    @Override
    protected AbstractPollingIoConnector<RawIoSession, RawIoChannel>.ConnectionRequest getConnectionRequest(
            RawIoChannel handle) {
        throw new UnsupportedOperationException();
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.polling.AbstractPollingIoConnector#init()
     */
    @Override
    protected void init() throws Exception {
        selector = new RawSelector(this,
                (DefaultRawSessionConfig) sessionConfig);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoConnector#newHandle(java
     * .net.SocketAddress)
     */
    @Override
    protected RawIoChannel newHandle(SocketAddress localAddress)
            throws Exception {
        RawIoChannel channel = new RawIoChannel(selector);
        channel.setLocalAddress(this.localAddr);
        return channel;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoConnector#newSession(org
     * .apache.mina.core.service.IoProcessor, java.lang.Object)
     */
    @Override
    protected RawIoSession newSession(IoProcessor<RawIoSession> processor,
            RawIoChannel handle) throws Exception {
        RawIoSession session = new RawIoSession(processor, this, handle);
        session.getConfig().setAll(getSessionConfig());
        return session;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.polling.AbstractPollingIoConnector#register(H,
     * org
     * .apache.mina.core.polling.AbstractPollingIoConnector.ConnectionRequest)
     */
    @Override
    protected void register(
            RawIoChannel arg0,
            AbstractPollingIoConnector<RawIoSession, RawIoChannel>.ConnectionRequest arg1)
            throws Exception {
        throw new UnsupportedOperationException();

    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.polling.AbstractPollingIoConnector#select(int)
     */
    @Override
    protected int select(int timeout) throws Exception {
        return 0;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoConnector#selectedHandles()
     */
    @Override
    protected Iterator<RawIoChannel> selectedHandles() {
        return Collections.EMPTY_LIST.iterator();
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.polling.AbstractPollingIoConnector#wakeup()
     */
    @Override
    protected void wakeup() {
        // Do nothing

    }

    /**
     * Process connections.
     *
     * @param handlers
     *            the handlers
     * @return the int
     */
    private int processConnections(Set<SelectionKey> handlers) {
        int nHandles = 0;
        Iterator it = handlers.iterator();
        // Loop on each connection request
        while (it.hasNext()) {
            SelectionKey sk = (SelectionKey) it.next();
            RawIoChannel handle = (RawIoChannel) sk.channel();
            it.remove();

            SelectionKey key = handle.keyFor(selector);

            if ((key == null) || (!key.isValid())) {
                continue;
            }

            ConnectionRequest connectionRequest = (ConnectionRequest) key
                    .attachment();

            if (connectionRequest == null) {
                continue;
            }
        }
        return nHandles;
    }
}
