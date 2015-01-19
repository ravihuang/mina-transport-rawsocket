package org.apache.mina.transport.rawsocket;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.mina.core.service.IoAcceptor;
import org.apache.mina.core.session.IdleStatus;
import org.jnetpcap.protocol.JProtocol;
import org.testng.annotations.Test;

public class Utils {
    
    @Test
    public void demo(){

        
                
    }
    
    /**
     * Hexs2b.
     *
     * @param hexstring
     *            the hexstring
     * @return the byte[]
     */
    public static byte[] hexs2b(String hexstring) {
        try {

            return (byte[]) new Hex().decode(hexstring.replaceAll(" |\n", ""));
        } catch (DecoderException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Mac2bs.
     *
     * @param hexstring
     *            the hexstring
     * @return the byte[]
     */
    public static byte[] mac2bs(String hexstring) {
        byte[] bs = chs2b(hexstring);

        if (bs.length != 6)
            throw new Error("wrong mac size!");

        return bs;
    }
    
    /**
     * B2h.
     *
     * @param b
     *            the b
     * @return the string
     */
    public static String b2h(byte b) {
        String tmp = Integer.toHexString(b);
        int len = tmp.length();
        if (len > 2)
            return tmp.substring(len - 2);

        return len == 1 ? ("0" + tmp) : tmp;
    }

    /**
     * Bs2chs.
     *
     * @param bs
     *            the bs
     * @param deli
     *            the deli
     * @return the string
     */
    public static String bs2chs(byte[] bs, String deli) {
        String s = "";
        if (bs == null || bs.length == 0)
            return s;

        for (int i = 0; i < bs.length - 1; i++) {
            s += b2h(bs[i]) + deli;
        }
        return s + b2h(bs[bs.length - 1]);
    }

    /**
     * Chs2b.
     *
     * @param colonstring
     *            the colonstring
     * @return the byte[]
     */
    public static byte[] chs2b(String colonstring) {
        String[] ss = colonstring.split("[.|:|-| ]");
        String s = "";
        for (int i = 0; i < ss.length; i++) {
            if (ss[i].length() % 2 == 1)
                ss[i] = "0" + ss[i];
            s += ss[i];
        }
        return hexs2b(s);
    }
    
    
}
