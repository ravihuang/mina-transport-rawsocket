package org.apache.mina.transport.rawsocket;

import java.nio.ByteBuffer;

public abstract class ARawLayer<T> implements IRawLayer<T>{
    protected byte[] content;
    
    @Override
    public ByteBuffer encode(ByteBuffer buf) {
        if(content!=null)
            buf.put(content);
        return buf;
    }
}
