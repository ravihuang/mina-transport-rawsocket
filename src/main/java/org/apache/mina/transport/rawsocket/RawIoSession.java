package org.apache.mina.transport.rawsocket;

import java.net.SocketAddress;
import java.nio.channels.SelectionKey;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.filterchain.DefaultIoFilterChain;
import org.apache.mina.core.filterchain.IoFilterChain;
import org.apache.mina.core.service.DefaultTransportMetadata;
import org.apache.mina.core.service.IoProcessor;
import org.apache.mina.core.service.IoService;
import org.apache.mina.core.service.TransportMetadata;
import org.apache.mina.core.session.AbstractIoSession;

public class RawIoSession extends AbstractIoSession {
    /** The Constant METADATA. */
    static final TransportMetadata METADATA = new DefaultTransportMetadata(
            "jnetpcap", "raw", true, false, EthAddress.class,
            DefaultRawSessionConfig.class, IoBuffer.class);

    /** The RawIoSession processor. */
    protected final IoProcessor<RawIoSession> processor;

    /** The communication channel. */
    protected final RawIoChannel channel;

    /** The SelectionKey used for this session. */
    protected SelectionKey key;

    /** The FilterChain created for this session. */
    private final IoFilterChain filterChain;
    
    private SocketAddress remoteAddress;

    /**
     * Instantiates a new raw io session.
     *
     * @param processor
     *            the processor
     * @param service
     *            the service
     * @param channel
     *            the channel
     */
    protected RawIoSession(IoProcessor<RawIoSession> processor,
            IoService service, RawIoChannel channel) {
        this(processor,service,channel,channel.getRemoteAddress());
    }
    
    protected RawIoSession(IoProcessor<RawIoSession> processor,
            IoService service, RawIoChannel channel,SocketAddress remoteAddress) {
        super(service);
        this.channel = channel;
        this.processor = processor;
        filterChain = new DefaultIoFilterChain(this);
        this.remoteAddress=remoteAddress;
        
        if (service instanceof RawIoAcceptor)
            this.config = ((RawIoAcceptor) service).get_session_config();
        else
            this.config = ((RawIoConnector) service).get_session_config();
    }
    /**
     * Gets the channel.
     *
     * @return the channel
     */
    public RawIoChannel getChannel() {
        return channel;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.session.IoSession#getFilterChain()
     */
    public IoFilterChain getFilterChain() {
        return filterChain;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.session.IoSession#getLocalAddress()
     */
    public SocketAddress getLocalAddress() {
        return channel.getLocalAddress();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public IoProcessor<RawIoSession> getProcessor() {
        return processor;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.session.IoSession#getRemoteAddress()
     */
    public SocketAddress getRemoteAddress() {
        return remoteAddress;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.session.IoSession#getTransportMetadata()
     */
    public TransportMetadata getTransportMetadata() {
        return METADATA;
    }

    /**
     * Gets the selection key.
     *
     * @return the selection key
     */
    SelectionKey getSelectionKey() {
        return key;
    }

    /**
     * Sets the selection key.
     *
     * @param key
     *            the new selection key
     */
    void setSelectionKey(SelectionKey key) {
        this.key = key;
    }
}
