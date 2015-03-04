package org.apache.mina.transport.rawsocket;

/*
 * #%L
 * iTDD UA Raw Socket
 * %%
 * Copyright (C) 2012 - 2013 Ravi Huang
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.packet.JPacket;

/**
 * dumper pcap packet to file
 * 
 * @author Ravi Huang
 *
 */
public class RawFileDumper {

    /** The filename. */
    String filename;

    /** The dumper. */
    private PcapDumper dumper;

    /** The is active. */
    private boolean isActive = false;

    /**
     * Instantiates a new raw file dumper.
     *
     * @param filename
     *            the filename
     */
    public RawFileDumper(String filename) {
        super();
        this.filename = filename;
    }

    /**
     * Dump.
     *
     * @param packet
     *            the packet
     */
    public void dump(JPacket packet) {
        dumper.dump(packet);
    }

    /**
     * Sets the up.
     *
     * @param pcap
     *            the new up
     */
    public void setup(Pcap pcap) {
        dumper = pcap.dumpOpen(filename);
        isActive = true;
    }

    /**
     * Teardown.
     */
    public void teardown() {
        dumper.close();
        dumper.flush();
    }
}
