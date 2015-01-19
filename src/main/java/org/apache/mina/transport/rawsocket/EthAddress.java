package org.apache.mina.transport.rawsocket;

import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;
import org.jnetpcap.protocol.JProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Class EthAddress.
 */
public class EthAddress extends SocketAddress {
    /**
     * 
     */
    private static final long serialVersionUID = -7707177261728737472L;
    
    // detail log switch
    public static boolean verbose = false;
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    
    static {
        alldevs = new ArrayList<PcapIf>();
        nes = new ArrayList<EthNE>();
        log = LoggerFactory.getLogger(EthAddress.class);
        init_all_if();
    }

    /** The Constant alldevs. */
    public final static List<PcapIf> alldevs;

    /** The Constant nes. */
    public final static List<EthNE> nes;

    /** The log. */
    private static Logger log;    
    
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * 根据本地网卡IP获得其MAC地址.
     *
     * @param ip
     *            the ip
     * @return the _addr_by_ip
     */
    public static EthAddress get_addr_by_ip(String ip) {
        EthNE ne = get_ne_by_ip(ip);
        if (ne != null)
            return new EthAddress(ne);
        return null;
    }

    /**
     * Gets the _addr_by_nic.
     *
     * @param nicname
     *            the nicname
     * @return the _addr_by_nic
     */
    public static EthAddress get_addr_by_nic(String nicname) {
        return null;
    }

    /**
     * Gets the _ne_by_ip.
     *
     * @param ip
     *            the ip
     * @return the _ne_by_ip
     */
    public static EthNE get_ne_by_ip(String ip) {
        byte[] ips = ip2b(ip);
        for (EthNE tmp : nes) {
            for (byte[] bb : tmp.get_ips()) {
                if (Arrays.equals(bb, ips)) {
                    tmp.set_id(ip);
                    return tmp;
                }
            }
        }
        return null;
    }
    private static byte[] ip2b(String ip) {
        try {
            return InetAddress.getByName(ip).getAddress();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return null;
    }
    /**
     * Init_all_if.
     */
    private static void init_all_if() {
        if (alldevs.size() > 0)
            return;

        StringBuilder errbuf = new StringBuilder();

        if ((Pcap.findAllDevs(alldevs, errbuf) != Pcap.OK || alldevs.isEmpty()))
            throw new IllegalArgumentException(
                    "Can't read list of devices, error is " + errbuf.toString());

        for (PcapIf d : alldevs) {
            log.debug("pcap if: {}", d);

            if (d.getFlags() != 0)
                continue;
            EthNE ne = new EthNE();
            try {
                ne.mac = d.getHardwareAddress();
            } catch (IOException e) {
                e.printStackTrace();
            }
            ne.name = d.getName();
            ne.desc = d.getDescription();

            for (PcapAddr addr : d.getAddresses()) {
                byte[] bip = addr.getAddr().getData().clone();
                if (bip.length == 4)
                    ne.ips.add(bip);
            }
            if (ne.ips.size() > 0)
                nes.add(ne);
        }
    }

    /** The nif. */
    private EthNE nif;

    /** The mac. */
    private byte[] mac;

    /** The eth type. */
    private int ethType = 0x88b8;

    /** The frame type. */
    private int frameType = JProtocol.ETHERNET_ID;
    
    private String ip;
    /**
     * Instantiates a new mac address.
     *
     * @param mac
     *            the mac
     */
    public EthAddress(byte[] mac) {
        if (mac.length != 6)
            throw new RuntimeException("wrong mac address");
        this.mac = mac;
    }

    /**
     * Instantiates a new mac address.
     *
     * @param nif
     *            the nif
     */
    public EthAddress(EthNE nif) {
        this.nif = nif;
        this.mac = nif.get_mac();
        ip=nif.get_id();
    }

    /**
     * Gets the eth type.
     *
     * @return the eth type
     */
    public int getEthType() {
        return ethType;
    }

    /**
     * Gets the frame type.
     *
     * @return the frame type
     */
    public int getFrameType() {
        return frameType;
    }
    public EthNE getNif() {
        return nif;
    }

    /**
     * Mac.
     *
     * @return the byte[]
     */
    public byte[] mac() {
        return mac;
    }

    /**
     * Sets the eth type.
     *
     * @param ethType
     *            the new eth type
     */
    public void setEthType(int ethType) {
        this.ethType = ethType;
    }

    /**
     * Sets the frame type.
     *
     * @param frameType
     *            the new frame type
     */
    public void setFrameType(int frameType) {
        this.frameType = frameType;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return nif + " " + bytesToHex(mac);
    }
}
