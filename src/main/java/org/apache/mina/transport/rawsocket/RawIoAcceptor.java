package org.apache.mina.transport.rawsocket;

import java.net.SocketAddress;
import java.nio.channels.ClosedSelectorException;
import java.nio.channels.SelectionKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.Semaphore;

import org.apache.mina.core.RuntimeIoException;
import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.service.AbstractIoAcceptor;
import org.apache.mina.core.service.IoProcessor;
import org.apache.mina.core.service.TransportMetadata;
import org.apache.mina.core.session.AbstractIoSession;
import org.apache.mina.core.session.ExpiringSessionRecycler;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.core.session.IoSessionConfig;
import org.apache.mina.core.session.IoSessionRecycler;
import org.apache.mina.core.write.WriteRequest;
import org.apache.mina.core.write.WriteRequestQueue;
import org.apache.mina.util.ExceptionMonitor;
import org.jnetpcap.packet.PcapPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RawIoAcceptor extends AbstractIoAcceptor implements
        IoProcessor<RawIoSession>, IRawFilter {
    /**
     * The Class Acceptor.
     */
    private class Acceptor implements Runnable {

        /*
         * (non-Javadoc)
         * 
         * @see java.lang.Runnable#run()
         */
        public void run() {
            int nHandles = 0;
            lastIdleCheckTime = System.currentTimeMillis();

            lock.release();

            while (selectable) {
                try {
                    int selected = select(SELECT_TIMEOUT);

                    nHandles += registerHandles();

                    if (nHandles == 0) {
                        try {
                            lock.acquire();

                            if (registerQueue.isEmpty()
                                    && cancelQueue.isEmpty()) {
                                acceptor = null;
                                break;
                            }
                        } finally {
                            lock.release();
                        }
                    }

                    if (selected > 0) {
                        processReadySessions(selector.selectedKeys());
                    }
                    long currentTime = System.currentTimeMillis();
                    nHandles -= unregisterHandles();

                    notifyIdleSessions(currentTime);
                } catch (ClosedSelectorException cse) {
                    // If the selector has been closed, we can exit the loop
                    ExceptionMonitor.getInstance().exceptionCaught(cse);
                    break;
                } catch (Exception e) {
                    ExceptionMonitor.getInstance().exceptionCaught(e);

                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e1) {
                    }
                }
            }

            if (selectable && isDisposing()) {
                selectable = false;
                try {
                    destroy();
                } catch (Exception e) {
                    ExceptionMonitor.getInstance().exceptionCaught(e);
                } finally {
                    disposalFuture.setValue(true);
                }
            }
        }
    }

    /** The Constant DEFAULT_RECYCLER. */
    private static final IoSessionRecycler DEFAULT_RECYCLER = new ExpiringSessionRecycler();

    private static Logger log = LoggerFactory.getLogger(RawIoAcceptor.class);

    /** The Constant SELECT_TIMEOUT. */
    private static final long SELECT_TIMEOUT = 1000L;

    /** The sessions. */
    protected LinkedList<RawIoSession> sessions = new LinkedList<RawIoSession>();

    /** The acceptor. */
    private Acceptor acceptor;

    /** The bound handles. */
    private final Map<SocketAddress, RawIoChannel> boundHandles = Collections
            .synchronizedMap(new HashMap<SocketAddress, RawIoChannel>());

    private boolean broadcast = false;

    /** The cancel queue. */
    private final Queue<AcceptorOperationFuture> cancelQueue = new ConcurrentLinkedQueue<AcceptorOperationFuture>();

    /** The disposal future. */
    private final ServiceOperationFuture disposalFuture = new ServiceOperationFuture();

    /** The flushing sessions. */
    private final Queue<RawIoSession> flushingSessions = new ConcurrentLinkedQueue<RawIoSession>();

    private boolean groupcast = false;

    /** The last idle check time. */
    private long lastIdleCheckTime;

    private EthAddress localAddr;

    /** The lock. */
    private final Semaphore lock = new Semaphore(1);

    /** The register queue. */
    private final Queue<AcceptorOperationFuture> registerQueue = new ConcurrentLinkedQueue<AcceptorOperationFuture>();

    /** The selectable. */
    private volatile boolean selectable;

    /** The selector. */
    private RawSelector selector;
    
    /** The session recycler. */
    private IoSessionRecycler sessionRecycler = DEFAULT_RECYCLER;
    
    private List<IRawLayer> tunnels;

    /**
     * Instantiates a new raw io acceptor.
     *
     * @param sessionConfig
     *            the session config
     */
    public RawIoAcceptor(DefaultRawSessionConfig sessionConfig) {
        this(sessionConfig, null);
    }

    /**
     * Instantiates a new raw io acceptor.
     *
     * @param sessionConfig
     *            the session config
     * @param executor
     *            the executor
     */
    public RawIoAcceptor(DefaultRawSessionConfig sessionConfig,
            Executor executor) {
        super(sessionConfig, executor);
        selectable = true;
        if(((DefaultRawSessionConfig)sessionConfig).getLocalBindingAddr()==null)
            throw new RuntimeException("sessionConfig.setLocalBindingAddr not set.");
               
        selector = new RawSelector(this, sessionConfig);
        localAddr=sessionConfig.getLocalBindingAddr();
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.service.IoProcessor#add(org.apache.mina.core.session
     * .IoSession)
     */
    public void add(RawIoSession session) {
        System.out.println("TODO");

    }

    public boolean direct_write(byte[] bs) {
        return selector.write(bs) == 0;
    }

    public RawPacket filter(PcapPacket packet) {
        RawPacket pkt = RawPacket.match_local_addr(packet, localAddr,
                this.broadcast, this.groupcast);        
        
        //TODO 匹配其他包头字段
        
        if (DefaultRawSessionConfig.verbose)
            log.debug("{} match:{} {}", localAddr, pkt!=null,packet);
        return pkt;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.service.IoProcessor#flush(org.apache.mina.core.session
     * .IoSession)
     */
    public void flush(RawIoSession session) {
        // TODO Auto-generated method stub

    }

    /**
     * Gets the _selector.
     *
     * @return the _selector
     */
    public RawSelector get_selector() {
        return this.selector;
    }

    /**
     * Gets the _session_config.
     *
     * @return the _session_config
     */
    public DefaultRawSessionConfig get_session_config() {
        return (DefaultRawSessionConfig) this.sessionConfig;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.service.IoService#getSessionConfig()
     */
    public IoSessionConfig getSessionConfig() {
        return this.sessionConfig;
    }

    /**
     * Gets the session recycler.
     *
     * @return the session recycler
     */
    public final IoSessionRecycler getSessionRecycler() {
        return sessionRecycler;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.service.IoService#getTransportMetadata()
     */
    public TransportMetadata getTransportMetadata() {
        return RawIoSession.METADATA;
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
     * @see
     * org.apache.mina.core.service.IoAcceptor#newSession(java.net.SocketAddress
     * , java.net.SocketAddress)
     */
    public IoSession newSession(SocketAddress remoteAddress,
            SocketAddress localAddress) {
        if (isDisposing()) {
            throw new IllegalStateException("Already disposed.");
        }

        if (remoteAddress == null) {
            throw new IllegalArgumentException("remoteAddress");
        }

        synchronized (bindLock) {
            if (!isActive()) {
                throw new IllegalStateException(
                        "Can't create a session from a unbound service.");
            }

            try {
                return newSessionWithoutLock(remoteAddress, localAddress);
            } catch (RuntimeException e) {
                throw e;
            } catch (Error e) {
                throw e;
            } catch (Exception e) {
                throw new RuntimeIoException("Failed to create a session.", e);
            }
        }

    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.service.IoProcessor#remove(org.apache.mina.core.
     * session.IoSession)
     */
    public void remove(RawIoSession session) {
        getSessionRecycler().remove(session);
        getListeners().fireSessionDestroyed(session);
    }

    /**
     * Remove_session.
     *
     * @param session
     *            the session
     */
    public void remove_session(RawIoSession session) {
        sessions.remove(session);
    }

    public void setTunnels(List<IRawLayer> tunnels){
        this.tunnels=tunnels;
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.service.IoProcessor#updateTrafficControl(org.apache
     * .mina.core.session.IoSession)
     */
    public void updateTrafficControl(RawIoSession session) {
        // TODO Auto-generated method stub

    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.service.IoProcessor#write(org.apache.mina.core.session
     * .IoSession, org.apache.mina.core.write.WriteRequest)
     */
    public void write(RawIoSession session, WriteRequest writeRequest) {
        long currentTime = System.currentTimeMillis();
        final WriteRequestQueue writeRequestQueue = session
                .getWriteRequestQueue();

        int writtenBytes = 0;

        // Deal with the special case of a Message marker (no bytes in the
        // request)
        // We just have to return after having calle dthe messageSent event
        IoBuffer buf = (IoBuffer) writeRequest.getMessage();

        if (buf.remaining() == 0) {
            // Clear and fire event
            session.setCurrentWriteRequest(null);
            buf.reset();
            session.getFilterChain().fireMessageSent(writeRequest);
            return;
        }

        // Now, write the data
        try {
            for (;;) {
                if (writeRequest == null) {
                    writeRequest = writeRequestQueue.poll(session);

                    if (writeRequest == null) {
                        break;
                    }

                    session.setCurrentWriteRequest(writeRequest);
                }

                buf = (IoBuffer) writeRequest.getMessage();

                if (buf.remaining() == 0) {
                    // Clear and fire event
                    session.setCurrentWriteRequest(null);
                    buf.reset();
                    session.getFilterChain().fireMessageSent(writeRequest);
                    continue;
                }

                int localWrittenBytes = session.getChannel().write(buf.buf(),session.getRemoteAddress());

                if (localWrittenBytes < 0) {
                    throw new RuntimeIoException("send fail");
                } else {
                    // Clear and fire event
                    session.setCurrentWriteRequest(null);
                    writtenBytes += localWrittenBytes;
                    buf.reset();
                    session.getFilterChain().fireMessageSent(writeRequest);
                    break;
                }
            }
        } catch (Exception e) {
            session.getFilterChain().fireExceptionCaught(e);
        } finally {
            session.increaseWrittenBytes(writtenBytes, currentTime);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.service.AbstractIoAcceptor#bindInternal(java.util
     * .List)
     */
    @Override
    protected Set<SocketAddress> bindInternal(
            List<? extends SocketAddress> localAddresses) throws Exception {
        AcceptorOperationFuture request = new AcceptorOperationFuture(
                localAddresses);
        registerQueue.add(request);
        startupAcceptor();

        lock.acquire();
        selector.wait_start();
        lock.release();

        request.awaitUninterruptibly();

        if (request.getException() != null) {
            throw request.getException();
        }

        // TODO
        Set<SocketAddress> newLocalAddresses = new HashSet<SocketAddress>();

        for (SocketAddress socketAddress : localAddresses) {
            if (socketAddress instanceof EthAddress) {
                newLocalAddresses.add(socketAddress);
                break;
            }
        }
        return newLocalAddresses;
    }

    /**
     * Close.
     *
     * @param handle
     *            the handle
     * @throws Exception
     *             the exception
     */
    protected void close(RawIoChannel handle) throws Exception {
        SelectionKey key = handle.keyFor(selector);

        if (key != null) {
            key.cancel();
        }
        handle.close();
    }

    /**
     * Destroy.
     *
     * @throws Exception
     *             the exception
     */
    protected void destroy() throws Exception {
        selectable = false;
        if (selector != null) {
            selector.close();
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.service.AbstractIoService#dispose0()
     */
    @Override
    protected void dispose0() throws Exception {
        selectable = false;
        unbind();
        startupAcceptor();
        selector.close();
    }

    /**
     * New session.
     *
     * @param processor
     *            the processor
     * @param handle
     *            the handle
     * @param remoteAddress
     *            the remote address
     * @return the raw io session
     */
    protected RawIoSession newSession(IoProcessor<RawIoSession> processor,
            RawIoChannel handle, SocketAddress remoteAddress) {
        SelectionKey key = handle.keyFor(selector);

        if ((key == null) || (!key.isValid())) {
            return null;
        }

        RawIoSession newSession = new RawIoSession(processor, this, handle,remoteAddress);
        newSession.setSelectionKey(key);

        return newSession;
    }

    /**
     * Select.
     *
     * @param timeout
     *            the timeout
     * @return the int
     * @throws Exception
     *             the exception
     */
    protected int select(long timeout) throws Exception {
        return selector.select(timeout);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.service.AbstractIoAcceptor#unbind0(java.util.List)
     */
    @Override
    protected void unbind0(List<? extends SocketAddress> localAddresses)
            throws Exception {
        AcceptorOperationFuture request = new AcceptorOperationFuture(
                localAddresses);

        cancelQueue.add(request);
        startupAcceptor();

        request.awaitUninterruptibly();

        if (request.getException() != null) {
            throw request.getException();
        }
    }

    /**
     * New session without lock.
     *
     * @param remoteAddress
     *            the remote address
     * @param localAddress
     *            the local address
     * @return the io session
     * @throws Exception
     *             the exception
     */
    private IoSession newSessionWithoutLock(SocketAddress remoteAddress,
            SocketAddress localAddress) throws Exception {
        RawIoChannel handle = boundHandles.get(localAddress);

        if (handle == null) {
            throw new IllegalArgumentException("Unknown local address: "
                    + localAddress);
        }

        IoSession session;

        synchronized (sessionRecycler) {
            session = sessionRecycler.recycle(remoteAddress);

            if (session != null) {
                return session;
            }

            // If a new session needs to be created.
            RawIoSession newSession = newSession(this, handle, remoteAddress);
            getSessionRecycler().put(newSession);
            session = newSession;
        }

        initSession(session, null, null);

        try {
            this.getFilterChainBuilder().buildFilterChain(
                    session.getFilterChain());
            getListeners().fireSessionCreated(session);
        } catch (Exception e) {
            ExceptionMonitor.getInstance().exceptionCaught(e);
        }

        return session;
    }

    /**
     * Notify idle sessions.
     *
     * @param currentTime
     *            the current time
     */
    private void notifyIdleSessions(long currentTime) {
        // process idle sessions
        if (currentTime - lastIdleCheckTime >= 1000) {
            lastIdleCheckTime = currentTime;
            AbstractIoSession.notifyIdleness(getListeners()
                    .getManagedSessions().values().iterator(), currentTime);
        }
    }

    /**
     * Process ready sessions.
     *
     * @param handles
     *            the handles
     */
    private void processReadySessions(Set<SelectionKey> handles) {
        Iterator<SelectionKey> iterator = handles.iterator();

        while (iterator.hasNext()) {
            SelectionKey key = iterator.next();
            RawIoChannel handle = (RawIoChannel) key.channel();
            iterator.remove();

            try {
                // if ((key != null) && key.isValid() && key.isReadable()) {
                if ((key != null) && key.isValid()) {
                    readHandle(handle);
                }

                if ((key != null) && key.isValid() && key.isWritable()) {
                    for (IoSession session : getManagedSessions().values()) {
                        scheduleFlush((RawIoSession) session);
                    }
                }
            } catch (Exception e) {
                ExceptionMonitor.getInstance().exceptionCaught(e);
            }
        }
    }

    /**
     * Read handle.
     *
     * @param handle
     *            the handle
     * @throws Exception
     *             the exception
     */
    private void readHandle(RawIoChannel handle) throws Exception {
        IoBuffer readBuf = IoBuffer.allocate(getSessionConfig()
                .getReadBufferSize());
        RawPacket pkt = handle.receive(readBuf.buf());
        EthAddress remoteAddress = new EthAddress(pkt.eth().source());

        IoSession session = newSessionWithoutLock(remoteAddress,
                handle.getLocalAddress());

        readBuf.flip();
        session.getFilterChain().fireMessageReceived(readBuf);

    }

    /**
     * Register handles.
     *
     * @return the int
     */
    private int registerHandles() {
        for (;;) {
            AcceptorOperationFuture req = registerQueue.poll();

            if (req == null) {
                break;
            }

            Map<SocketAddress, RawIoChannel> newHandles = new HashMap<SocketAddress, RawIoChannel>();
            List<SocketAddress> localAddresses = req.getLocalAddresses();

            try {
                for (SocketAddress socketAddress : localAddresses) {
                    RawIoChannel handle = new RawIoChannel(selector,tunnels);
                    handle.setLocalAddress(this.localAddr);

                    handle.configureBlocking(false);
                    handle.register(selector, SelectionKey.OP_READ);
                    newHandles.put(handle.getLocalAddress(), handle);
                }

                boundHandles.putAll(newHandles);

                getListeners().fireServiceActivated();

                req.setDone();

                return newHandles.size();
            } catch (Exception e) {
                req.setException(e);
            } finally {
                // Roll back if failed to bind all addresses.
                if (req.getException() != null) {
                    for (RawIoChannel handle : newHandles.values()) {
                        try {
                            close(handle);
                        } catch (Exception e) {
                            ExceptionMonitor.getInstance().exceptionCaught(e);
                        }
                    }

                    selector.wakeup();
                }
            }
        }

        return 0;
    }

    /**
     * Schedule flush.
     *
     * @param session
     *            the session
     * @return true, if successful
     */
    private boolean scheduleFlush(RawIoSession session) {
        if (session.setScheduledForFlush(true)) {
            flushingSessions.add(session);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Startup acceptor.
     *
     * @throws InterruptedException
     *             the interrupted exception
     */
    private void startupAcceptor() throws InterruptedException {
        if (!selectable) {
            registerQueue.clear();
        }

        lock.acquire();

        if (acceptor == null) {
            acceptor = new Acceptor();
            executeWorker(acceptor);
        } else {
            lock.release();
        }
    }

    /**
     * Unregister handles.
     *
     * @return the int
     */
    private int unregisterHandles() {
        int nHandles = 0;

        for (;;) {
            AcceptorOperationFuture request = cancelQueue.poll();
            if (request == null) {
                break;
            }

            // close the channels
            for (SocketAddress socketAddress : request.getLocalAddresses()) {
                RawIoChannel handle = boundHandles.remove(socketAddress);

                if (handle == null) {
                    continue;
                }

                try {
                    close(handle);
                    selector.wakeup(); // wake up again to trigger thread death
                } catch (Exception e) {
                    ExceptionMonitor.getInstance().exceptionCaught(e);
                } finally {
                    nHandles++;
                }
            }

            request.setDone();
        }

        return nHandles;
    }
}
