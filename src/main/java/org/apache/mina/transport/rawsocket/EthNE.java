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

import java.util.ArrayList;

public class EthNE {

    /** The mac. */
    byte[] mac;

    /** The name. */
    String name;

    /** The desc. */
    String desc;

    /** The id. */
    private String id;

    /** The ips. */
    ArrayList<byte[]> ips = new ArrayList<byte[]>();

    /**
     * Gets the _desc.
     *
     * @return the _desc
     */
    public String get_desc() {
        return desc;
    }

    /**
     * Gets the _ips.
     *
     * @return the _ips
     */
    public ArrayList<byte[]> get_ips() {
        return ips;
    }

    /**
     * Gets the _mac.
     *
     * @return the _mac
     */
    public byte[] get_mac() {
        return mac;
    }

    /**
     * Gets the _name.
     *
     * @return the _name
     */
    public String get_name() {
        return name;
    }

    /**
     * Sets the _id.
     *
     * @param id
     *            the new _id
     */
    public void set_id(String id) {
        this.id = id;
    }
    public String get_id() {
        return id;
    }
    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return id;
    }
}
