package org.apache.mina.transport.rawsocket;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.IllegalSelectorException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.spi.AbstractSelectableChannel;
import java.nio.channels.spi.AbstractSelector;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RawSelector extends AbstractSelector {
    /** The log. */
    private static Logger log = LoggerFactory.getLogger(RawSelector.class);

    /** The public keys. */
    private Set<SelectionKey> publicKeys = new HashSet<SelectionKey>();;

    /** The public selected keys. */
    private Set<SelectionKey> publicSelectedKeys = new HashSet<SelectionKey>();

    /** The queue. */
    private BlockingQueue<RawPacket> queue = new LinkedBlockingQueue<RawPacket>();

    IRawFilter filter;

    RawIoPoll poll;

    /**
     * Instantiates a new raw selector.
     *
     * @param sessionconfig
     *            the sessionconfig
     */
    public RawSelector(IRawFilter filter, DefaultRawSessionConfig sessionconfig) {
        super(null);
        this.filter = filter;
        poll = RawIoPoll.get_poll(sessionconfig);
        poll.set_name(filter.getClass().getSimpleName());
        poll.register_selector(this);

        if (!poll.is_started())
            poll.startCapture();

        // publicKeys = Collections.unmodifiableSet(new
        // HashSet<SelectionKey>());
    }

    public DefaultRawSessionConfig get_config() {
        return poll.get_config();
    }

    /**
     * Checks if is _started.
     *
     * @return true, if is _started
     */
    public boolean is_started() {
        return poll.is_started();
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.nio.channels.Selector#keys()
     */
    @Override
    public Set<SelectionKey> keys() {
        return publicKeys;
    }
    
    public boolean match(PcapPacket pkt) {
        RawPacket tmp = this.filter.filter(pkt);
        if (tmp != null) {
            this.queue.add(tmp);
            return true;
        }
        return false;

    }

    /*
     * (non-Javadoc)
     * 
     * @see java.nio.channels.Selector#select()
     */
    @Override
    public int select() throws IOException {
        return select(0);
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.nio.channels.Selector#select(long)
     */
    @Override
    public int select(long timeout) throws IOException {
        // if (publicKeys == null||publicSelectedKeys==null||queue==null){
        // log.debug("publicKeys is null {}", this);
        // return 0;
        // }
        long c = System.currentTimeMillis();
        try {
            RawPacket pkt = queue.poll(timeout, TimeUnit.MILLISECONDS);
            if (pkt == null)
                return 0;

            for (SelectionKey tmp : publicKeys) {
                RawIoChannel ch = (RawIoChannel) tmp.channel();
                if (ch.filter(pkt)) {
                    ch.add(pkt);
                    this.publicSelectedKeys.add(tmp);
                }
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        log.debug("time:{}", System.currentTimeMillis() - c);
        // log.debug("{} {}",this,publicSelectedKeys.size());
        return publicSelectedKeys.size();

    }

    /*
     * (non-Javadoc)
     * 
     * @see java.nio.channels.Selector#selectedKeys()
     */
    @Override
    public Set<SelectionKey> selectedKeys() {
        return publicSelectedKeys;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.nio.channels.Selector#selectNow()
     */
    @Override
    public int selectNow() throws IOException {
        return select(0);
    }

    public void teardown() {
        poll.close();
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.nio.channels.Selector#wakeup()
     */
    @Override
    public Selector wakeup() {        
        return this;
    }
    
    public void wait_start(){
        poll.wait_start();
    }
    
    /**
     * Write.
     *
     * @param msg
     *            the msg
     * @return the int
     */
    public int write(byte[] msg) {
        log.debug("time:{}", System.currentTimeMillis());
        return poll.pcap().sendPacket(msg);
    }

    /**
     * Write.
     *
     * @param buffer
     *            the buffer
     * @return the int
     */
    public int write(ByteBuffer buffer) {
        log.debug("time:{}", System.currentTimeMillis());
        return poll.pcap().sendPacket(buffer);
    }

    /**
     * Write.
     *
     * @param buffer
     *            the buffer
     * @return the int
     */
    public int write(JBuffer buffer) {
        log.debug("time:{}", System.currentTimeMillis());
        return poll.pcap().sendPacket(buffer);

    }

    /**
     * Write.
     *
     * @param msg
     *            the msg
     * @return the int
     */
    public int write(JPacket msg) {
        log.debug("time:{}", System.currentTimeMillis());
        return poll.pcap().sendPacket(msg);
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.nio.channels.spi.AbstractSelector#implCloseSelector()
     */
    @Override
    protected void implCloseSelector() throws IOException {
        synchronized (this) {
            teardown();
            synchronized (publicKeys) {
                synchronized (publicSelectedKeys) {
                    publicSelectedKeys = null;
                    publicKeys = null;
                }
            }
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * java.nio.channels.spi.AbstractSelector#register(java.nio.channels.spi
     * .AbstractSelectableChannel, int, java.lang.Object)
     */
    @Override
    protected SelectionKey register(AbstractSelectableChannel ch, int ops,
            Object attachment) {
        if (!(ch instanceof RawIoChannel))
            throw new IllegalSelectorException();
        RawSelectionKey k = new RawSelectionKey((RawIoChannel) ch, this);
        k.attach(attachment);
        synchronized (publicKeys) {
            publicKeys.add(k);
        }
        k.interestOps(ops);
        return k;
    }

    RawIoPoll get_io_poller() {
        return poll;
    }

}
