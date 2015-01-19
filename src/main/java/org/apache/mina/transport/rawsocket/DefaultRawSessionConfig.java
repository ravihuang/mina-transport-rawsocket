package org.apache.mina.transport.rawsocket;

import org.apache.mina.core.session.AbstractIoSessionConfig;
import org.apache.mina.core.session.IoSessionConfig;
import org.jnetpcap.Pcap;
import org.jnetpcap.protocol.JProtocol;

public class DefaultRawSessionConfig extends AbstractIoSessionConfig {
    
    /** The connect timeout in millis. */
    private long connectTimeoutInMillis;
    
    /** The err buffer. */
    private StringBuilder errBuffer = new StringBuilder();
    
    /** The filter. */
    private String filter;
    
    public static final int DEFAULT_FRAME_TYPE=JProtocol.ETHERNET_ID;
    
    /** The lcladdr. */
    private EthAddress lcladdr;
    
    /** The loop. */
    private int loop = -1;
    
    private String name;
    
    /** The need capture. */
    private boolean needCapture = true;
    
    /** The netmask. */
    private int netmask = 0xFFFFFF00;
    
    /** The optimize. */
    private int optimize = 0;
    
    /** The promisc. */
    private int promisc = Pcap.MODE_NON_PROMISCUOUS;
    
    /** The protocol id. */
    private int protocolId;
    
    /** The snaplen. */
    private int snaplen = 2000;
    
    /** The timeout. */
    private int timeout = 1000;
    /** The user. */
    private String user = "ate";
     
    private String dumperFilename;
    
    public DefaultRawSessionConfig(){}
    
    public DefaultRawSessionConfig(EthAddress lcladdr){
        this.lcladdr=lcladdr;
    }
    
    /**
     * Gets the connect timeout millis.
     *
     * @return the connect timeout millis
     */
    public final long getConnectTimeoutMillis() {
        return connectTimeoutInMillis;
    }
    
    public String getDumperFilename() {
        return dumperFilename;
    }
    
    /**
     * Gets the err buffer.
     *
     * @return the err buffer
     */
    public StringBuilder getErrBuffer() {
        return errBuffer;
    }
    
    /**
     * Gets the filter.
     *
     * @return the filter
     */
    public String getFilter() {
        return filter;
    }

    /**
     * Gets the local mac addr.
     *
     * @return the local mac addr
     */
    public EthAddress getLocalBindingAddr() {
        return lcladdr;
    }

    /**
     * Gets the loop.
     *
     * @return the loop
     */
    public int getLoop() {
        return loop;
    }

    /**
     * Gets the mac addr by ip.
     *
     * @param ip the ip
     * @return the mac addr by ip
     */
    public EthAddress getMacAddrByIp(String ip) {
        return EthAddress.get_addr_by_ip(ip);
    }

    public String getName() {
        return name;
    }

    /**
     * Gets the netmask.
     *
     * @return the netmask
     */
    public int getNetmask() {
        return netmask;
    }

    /**
     * Gets the optimize.
     *
     * @return the optimize
     */
    public int getOptimize() {
        return optimize;
    }

    /**
     * Gets the promisc.
     *
     * @return the promisc
     */
    public int getPromisc() {
        return promisc;
    }

    /**
     * Gets the protocol id.
     *
     * @return the protocol id
     */
    public int getProtocolId() {
        return protocolId;
    }

    /**
     * Gets the snaplen.
     *
     * @return the snaplen
     */
    public int getSnaplen() {
        return snaplen;
    }

    /**
     * Gets the timeout.
     *
     * @return the timeout
     */
    public int getTimeout() {
        return timeout;
    }

    /**
     * Gets the user.
     *
     * @return the user
     */
    public String getUser() {
        return user;
    }

    /**
     * Checks if is need capture.
     *
     * @return true, if is need capture
     */
    public boolean isNeedCapture() {
        return needCapture;
    }

    /**
     * Sets the dumper filename.
     *
     * @param dumperFilename the new dumper filename
     */
    public void setDumperFilename(String dumperFilename) {
        this.dumperFilename = dumperFilename;
    }
    
    /**
     * Sets the err buffer.
     *
     * @param errBuffer the new err buffer
     */
    public void setErrBuffer(StringBuilder errBuffer) {
        this.errBuffer = errBuffer;
    }

    /**
     * Sets the filter.
     *
     * @param filter the new filter
     */
    public void setFilter(String filter) {
        this.filter = filter;
    }

    /**
     * Sets the local mac addr.
     *
     * @param macaddr the new local mac addr
     */
    public void setLocalEthAddr(EthAddress macaddr) {
        if(macaddr==null)
            throw new RuntimeException("setLocalEthAddr cant be null");
        this.lcladdr = macaddr;
    }

    /**
     * Sets the loop.
     *
     * @param loop the new loop
     */
    public void setLoop(int loop) {
        this.loop = loop;
    }

    public void setName(String name) {
        this.name = name;
    }

    /**
     * Sets the need capture.
     *
     * @param needCapture the new need capture
     */
    public void setNeedCapture(boolean needCapture) {
        this.needCapture = needCapture;
    }

    /**
     * Sets the netmask.
     *
     * @param netmask the new netmask
     */
    public void setNetmask(int netmask) {
        this.netmask = netmask;
    }

    /**
     * Sets the optimize.
     *
     * @param optimize the new optimize
     */
    public void setOptimize(int optimize) {
        this.optimize = optimize;
    }

    /**
     * Sets the promisc.
     *
     * @param promisc the new promisc
     */
    public void setPromisc(int promisc) {
        this.promisc = promisc;
    }

    /**
     * Sets the protocol id.
     *
     * @param protocolId the new protocol id
     */
    public void setProtocolId(int protocolId) {
        this.protocolId = protocolId;
    }

    /**
     * Sets the snaplen.
     *
     * @param snaplen the new snaplen
     */
    public void setSnaplen(int snaplen) {
        this.snaplen = snaplen;
    }

    /**
     * Sets the timeout.
     *
     * @param timeout the new timeout
     */
    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    /**
     * Sets the user.
     *
     * @param user the new user
     */
    public void setUser(String user) {
        this.user = user;
    }

    /* (non-Javadoc)
     * @see org.apache.mina.core.session.AbstractIoSessionConfig#doSetAll(org.apache.mina.core.session.IoSessionConfig)
     */
    @Override
    protected void doSetAll(IoSessionConfig config) {
        if (config instanceof DefaultRawSessionConfig) {
            DefaultRawSessionConfig cfg = (DefaultRawSessionConfig) config;
            setSnaplen(cfg.getSnaplen());
            setPromisc(cfg.getPromisc());
            setTimeout(cfg.getTimeout());
            setNeedCapture(cfg.isNeedCapture());
            setProtocolId(cfg.getProtocolId());
            setFilter(cfg.getFilter());            
            setUser(cfg.getUser());
            this.setLoop(cfg.getLoop());
            this.setOptimize(cfg.getOptimize());
            this.setNetmask(cfg.getNetmask());

        }
    }

}
