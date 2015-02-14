package org.apache.mina.transport.rawsocket;

import java.util.Hashtable;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JNetpcap Wrapper
 * @author Ravi Huang
 *
 */
class RawIoPoll implements Runnable, PcapPacketHandler {
    private static Logger log = LoggerFactory.getLogger(RawIoPoll.class);
    private static Hashtable<EthNE, RawIoPoll> devices = new Hashtable();
    public static int MTU=1512;
    public static int MITU=60;

    public static RawIoPoll get_poll(DefaultRawSessionConfig sessionconfig) {
        EthNE device = sessionconfig.getLocalBindingAddr().getNif();
        if (devices.get(device) != null)
            return devices.get(device);
        else {
            RawIoPoll poll = new RawIoPoll(sessionconfig);
            devices.put(device, poll);
            return poll;
        }
    }

    /** The device. */
    private EthNE device = null;

    /** The dumper. */
    private RawFileDumper dumper;

    /** The id datalink. */
    private int ID_DATALINK;

    /** The pcap. */
    private Pcap pcap;

    /** The isstarted. */
    private boolean isstarted = false;

    /** The iswakeup. */
    private boolean iswakeup = false;

    /** The config. */
    private DefaultRawSessionConfig config;

    /** The name. */
    private String name = "";

    private Hashtable<RawSelector, Integer> selectors = new Hashtable<RawSelector, Integer>();

    private RawIoPoll(DefaultRawSessionConfig sessionconfig) {
        this.config = sessionconfig;
        
        device = config.getLocalBindingAddr().getNif();
        if (config.getDumperFilename() != null)
            dumper = new RawFileDumper(config.getDumperFilename());
        
        this.set_name(config.getName());

        // publicKeys = Collections.unmodifiableSet(new
        // HashSet<SelectionKey>());
    }

    public void close() {
        iswakeup = false;
        isstarted = false;
        if (dumper != null)
            dumper.teardown();
        try {
            pcap.breakloop();
            pcap.close();
        } catch (Exception e) {
            // e.printStackTrace();
        } finally {
            devices.remove(this.device);
        }
    }

    public void deregister_selector(RawSelector sel) {
        Integer i = selectors.get(sel);
        if (i > 0) {
            i--;
            this.selectors.put(sel, i);
        }
    }

    /**
     * Gets the _config.
     *
     * @return the _config
     */
    public DefaultRawSessionConfig get_config() {
        return config;
    }

    /**
     * Checks if is _started.
     *
     * @return true, if is _started
     */
    public boolean is_started() {
        return isstarted;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.jnetpcap.packet.PcapPacketHandler#nextPacket(org.jnetpcap.packet.
     * PcapPacket, java.lang.Object)
     */
    public void nextPacket(PcapPacket packet, Object user) {
        log.debug("{} receive size: {} ", this, packet.size());

        if (!iswakeup)
            return;

        for (RawSelector sel : selectors.keySet()) {
            // 一个包只能匹配一种IoService
            if (sel.match(packet)) {
                if (dumper != null)
                    dumper.dump(packet);
                break;
            }
        }        
    }

    public Pcap pcap() {
        return this.pcap;
    }

    public void register_selector(RawSelector sel) {
        Integer i = selectors.get(sel);
        if (i == null)
            i = new Integer(0);
        i++;
        selectors.put(sel, 1);
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Runnable#run()
     */
    public void run() {
        pcap = Pcap
                .openLive(device.get_name(), config.getSnaplen(),
                        config.getPromisc(), config.getTimeout(),
                        config.getErrBuffer());
        ID_DATALINK = JRegistry.mapDLTToId(pcap.datalink());

        if (!config.isNeedCapture())
            return;

        if (dumper != null)
            dumper.setup(pcap);

        if (config.getFilter() != null) {
            PcapBpfProgram fp = new PcapBpfProgram();
            int q = pcap.compile(fp, config.getFilter(), config.getOptimize(),
                    config.getNetmask());

            if (q != Pcap.OK)
                log.warn("Filter error: " + pcap.getErr());
            else {
                log.debug("Applying pcap filter");
                if (pcap.setFilter(fp) != Pcap.OK)
                    log.warn("Error durin applying pcap filter:"
                            + pcap.getErr());
            }
        }
        isstarted = true;
        // new Thread(new Processor()).start();

        pcap.loop(config.getLoop(), this, this.config.getUser());
        isstarted = false;

        // log.debug("run exit: " + pcap.getErr());
    }

    /**
     * Sets the _file_dumper.
     *
     * @param filename
     *            the new _file_dumper
     */
    public void set_file_dumper(String filename) {
        dumper = new RawFileDumper(filename);
    }

    /**
     * Sets the _name.
     *
     * @param name
     *            the new _name
     */
    public void set_name(String name) {
        if(name==null||this.name!=null)
            return;
        this.name = name;
    }

    /**
     * Start capture.
     */
    public void startCapture() {
        // 保证同一个device只启动一次
        synchronized (this) {
            if (!this.isstarted) {
                new Thread(this).start();
                wait_start();
            }

        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return device + " " + name;
    }

    public boolean wait_start() {
        if (iswakeup)
            return true;
        long c = System.currentTimeMillis();
        int i = 100;
        int activated = -1;
        while (i-- > 0
                && (!this.is_started() || (activated = pcap.activate()) != 0)) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
            }
        }
        iswakeup = (activated == 0);
        log.debug("time:{}", System.currentTimeMillis() - c);
        return iswakeup;
    }
}
