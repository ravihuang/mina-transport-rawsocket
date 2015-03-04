package org.apache.mina.transport.rawsocket;

import java.io.IOException;
import java.nio.channels.ByteChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Collections;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.Executor;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.file.FileRegion;
import org.apache.mina.core.polling.AbstractPollingIoProcessor;
import org.apache.mina.core.session.SessionState;

public class RawProcessor extends AbstractPollingIoProcessor<RawIoSession> {

    /**
     * An encapsulating iterator around the {@link Selector#selectedKeys()} or
     * the {@link Selector#keys()} iterator;.
     *
     * @param <RawIoSession>
     *            the generic type
     */
    protected static class IoSessionIterator<RawIoSession> implements
            Iterator<RawIoSession> {

        /** The iterator. */
        private final Iterator<SelectionKey> iterator;

        /**
         * Create this iterator as a wrapper on top of the selectionKey Set.
         *
         * @param keys
         *            The set of selected sessions
         */
        private IoSessionIterator(Set<SelectionKey> keys) {
            iterator = keys.iterator();
        }

        /**
         * {@inheritDoc}
         */
        public boolean hasNext() {
            return iterator.hasNext();
        }

        /**
         * {@inheritDoc}
         */
        public RawIoSession next() {
            SelectionKey key = iterator.next();
            RawIoSession nioSession = (RawIoSession) key.attachment();
            return nioSession;
        }

        /**
         * {@inheritDoc}
         */
        public void remove() {
            iterator.remove();
        }
    }

    /** The selector. */
    RawSelector selector;

    /**
     * Instantiates a new raw processor.
     *
     * @param executor
     *            the executor
     */
    public RawProcessor(Executor executor) {
        super(executor);
    }

    /**
     * Sets the selector.
     *
     * @param selector
     *            the new selector
     */
    public void setSelector(RawSelector selector) {
        this.selector = selector;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoProcessor#allSessions()
     */
    @Override
    protected Iterator<RawIoSession> allSessions() {
        Set<SelectionKey> keys = selector.keys();
        if (keys == null)
            keys = Collections.EMPTY_SET;
        return new IoSessionIterator(keys);

    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoProcessor#destroy(org.apache
     * .mina.core.session.AbstractIoSession)
     */
    @Override
    protected void destroy(RawIoSession session) throws Exception {
        ByteChannel ch = session.getChannel();
        SelectionKey key = session.getSelectionKey();
        if (key != null) {
            key.cancel();
        }
        ch.close();
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.polling.AbstractPollingIoProcessor#doDispose()
     */
    @Override
    protected void doDispose() throws Exception {
        super.dispose();
        selector.close();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected SessionState getState(RawIoSession session) {
        SelectionKey key = session.getSelectionKey();

        if (key == null) {
            // The channel is not yet registred to a selector
            return SessionState.OPENING;
        }

        if (key.isValid()) {
            // The session is opened
            return SessionState.OPENED;
        } else {
            // The session still as to be closed
            return SessionState.CLOSING;
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoProcessor#init(org.apache
     * .mina.core.session.AbstractIoSession)
     */
    @Override
    protected void init(RawIoSession session) throws Exception {
        RawIoChannel ch = session.getChannel();
        ch.configureBlocking(false);
        session.setSelectionKey(ch.register(selector, SelectionKey.OP_READ,
                session));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected boolean isBrokenConnection() throws IOException {
        // A flag set to true if we find a broken session
        boolean brokenSession = false;

        synchronized (selector) {
            // Get the selector keys
            Set<SelectionKey> keys = selector.keys();

            // Loop on all the keys to see if one of them
            // has a closed channel
            for (SelectionKey key : keys) {
                SelectableChannel channel = key.channel();

                if ((((channel instanceof RawIoChannel) && !((RawIoChannel) channel)
                        .isConnected()))) {
                    // The channel is not connected anymore. Cancel
                    // the associated key then.
                    key.cancel();

                    // Set the flag to true to avoid a selector switch
                    brokenSession = true;
                }
            }
        }

        return brokenSession;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoProcessor#isInterestedInRead
     * (org.apache.mina.core.session.AbstractIoSession)
     */
    @Override
    protected boolean isInterestedInRead(RawIoSession session) {
        SelectionKey key = session.getSelectionKey();
        return (key != null) && key.isValid()
                && ((key.interestOps() & SelectionKey.OP_READ) != 0);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoProcessor#isInterestedInWrite
     * (org.apache.mina.core.session.AbstractIoSession)
     */
    @Override
    protected boolean isInterestedInWrite(RawIoSession session) {
        SelectionKey key = session.getSelectionKey();
        return (key != null) && key.isValid()
                && ((key.interestOps() & SelectionKey.OP_WRITE) != 0);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoProcessor#isReadable(org
     * .apache.mina.core.session.AbstractIoSession)
     */
    @Override
    protected boolean isReadable(RawIoSession session) {
        return true;
        // 不处理ops
        // SelectionKey key = session.getSelectionKey();
        // return (key != null) && key.isValid() && key.isReadable();
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoProcessor#isSelectorEmpty()
     */
    @Override
    protected boolean isSelectorEmpty() {
        if (selector.keys() == null)
            return true;
        return selector.keys().isEmpty();
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoProcessor#isWritable(org
     * .apache.mina.core.session.AbstractIoSession)
     */
    @Override
    protected boolean isWritable(RawIoSession session) {
        // 不处理ops
        return true;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoProcessor#read(org.apache
     * .mina.core.session.AbstractIoSession,
     * org.apache.mina.core.buffer.IoBuffer)
     */
    @Override
    protected int read(RawIoSession session, IoBuffer buf) throws Exception {
        ByteChannel channel = session.getChannel();

        return channel.read(buf.buf());
    }

    /**
     * In the case we are using the java select() method, this method is used to
     * trash the buggy selector and create a new one, registering all the
     * sockets on it.
     *
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     */
    @Override
    protected void registerNewSelector() throws IOException {
        throw new Error("unsupported method");
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.polling.AbstractPollingIoProcessor#select()
     */
    @Override
    protected int select() throws Exception {
        return selector.select();
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.polling.AbstractPollingIoProcessor#select(long)
     */
    @Override
    protected int select(long timeout) throws Exception {
        return selector.select(timeout);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoProcessor#selectedSessions
     * ()
     */
    @SuppressWarnings("synthetic-access")
    @Override
    protected Iterator<RawIoSession> selectedSessions() {
        return new IoSessionIterator(selector.selectedKeys());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void setInterestedInRead(RawIoSession session,
            boolean isInterested) throws Exception {
        SelectionKey key = session.getSelectionKey();

        if ((key == null) || !key.isValid()) {
            return;
        }

        int oldInterestOps = key.interestOps();
        int newInterestOps = oldInterestOps;

        if (isInterested) {
            newInterestOps |= SelectionKey.OP_READ;
        } else {
            newInterestOps &= ~SelectionKey.OP_READ;
        }

        if (oldInterestOps != newInterestOps) {
            key.interestOps(newInterestOps);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void setInterestedInWrite(RawIoSession session,
            boolean isInterested) throws Exception {
        SelectionKey key = session.getSelectionKey();

        if ((key == null) || !key.isValid()) {
            return;
        }

        int newInterestOps = key.interestOps();

        if (isInterested) {
            newInterestOps |= SelectionKey.OP_WRITE;
        } else {
            newInterestOps &= ~SelectionKey.OP_WRITE;
        }

        key.interestOps(newInterestOps);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoProcessor#transferFile(
     * org.apache.mina.core.session.AbstractIoSession,
     * org.apache.mina.core.file.FileRegion, int)
     */
    @Override
    protected int transferFile(RawIoSession session, FileRegion region,
            int length) throws Exception {
        try {
            return (int) region.getFileChannel().transferTo(
                    region.getPosition(), length, session.getChannel());
        } catch (IOException e) {
            // Check to see if the IOException is being thrown due to
            // http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=5103988
            String message = e.getMessage();
            if ((message != null)
                    && message.contains("temporarily unavailable")) {
                return 0;
            }

            throw e;
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.mina.core.polling.AbstractPollingIoProcessor#wakeup()
     */
    @Override
    protected void wakeup() {
        wakeupCalled.getAndSet(true);
        selector.wakeup();
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.mina.core.polling.AbstractPollingIoProcessor#write(org.apache
     * .mina.core.session.AbstractIoSession,
     * org.apache.mina.core.buffer.IoBuffer, int)
     */
    @Override
    protected int write(RawIoSession session, IoBuffer buf, int length)
            throws Exception {
        if (buf.remaining() <= length) {
            return session.getChannel().write(buf.buf());
        }

        int oldLimit = buf.limit();
        buf.limit(buf.position() + length);
        try {
            return session.getChannel().write(buf.buf());
        } finally {
            buf.limit(oldLimit);
        }
    }
}
