package org.apache.mina.transport.rawsocket;

import java.nio.channels.CancelledKeyException;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.spi.AbstractSelectionKey;

public class RawSelectionKey extends AbstractSelectionKey {

    /** The channel. */
    final RawIoChannel channel;

    /** The selector. */
    final RawSelector selector;

    /** The interest ops. */
    private volatile int interestOps;

    /** The ready ops. */
    private int readyOps;

    /**
     * Instantiates a new raw selection key.
     *
     * @param ch
     *            the ch
     * @param sel
     *            the sel
     */
    protected RawSelectionKey(RawIoChannel ch, RawSelector sel) {
        channel = ch;
        selector = sel;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.nio.channels.SelectionKey#channel()
     */
    @Override
    public SelectableChannel channel() {
        return channel;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.nio.channels.SelectionKey#interestOps()
     */
    @Override
    public int interestOps() {
        ensureValid();
        return interestOps;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.nio.channels.SelectionKey#interestOps(int)
     */
    @Override
    public SelectionKey interestOps(int ops) {
        ensureValid();
        return nioInterestOps(ops);
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.nio.channels.SelectionKey#readyOps()
     */
    @Override
    public int readyOps() {
        // TODO
        // ensureValid();
        return 1;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.nio.channels.SelectionKey#selector()
     */
    @Override
    public Selector selector() {
        return selector;
    }

    /**
     * Nio interest ops.
     *
     * @return the int
     */
    int nioInterestOps() { // package-private
        return interestOps;
    }

    /**
     * Nio interest ops.
     *
     * @param ops
     *            the ops
     * @return the selection key
     */
    SelectionKey nioInterestOps(int ops) { // package-private
        if ((ops & ~channel().validOps()) != 0)
            throw new IllegalArgumentException();
        channel.translateAndSetInterestOps(ops, this);
        interestOps = ops;
        return this;
    }

    /**
     * Nio ready ops.
     *
     * @return the int
     */
    int nioReadyOps() { // package-private
        return readyOps;
    }

    /**
     * Nio ready ops.
     *
     * @param ops
     *            the ops
     */
    void nioReadyOps(int ops) { // package-private
        readyOps = ops;
    }

    /**
     * Ensure valid.
     */
    private void ensureValid() {
        if (!isValid())
            throw new CancelledKeyException();
    }

}
