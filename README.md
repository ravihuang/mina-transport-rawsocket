# Apache Mina Transport Rawsocket
Apache mina Rawsocket Transport

Using native library jnetpcap 1.4.r1425 from: http://jnetpcap.com/download

please see: https://mina.apache.org/mina-project/userguide/ch6-transports/serial-transport.html

# IoAcceptor for a NIC(network interface card)
    //10.10.10.1 is one of nic's ip addresses
    EthAddress addr1=EthAddress.get_addr_by_ip("10.10.10.1");        
    addr.setEthType(0x0800);        
    addr.setFrameType(JProtocol.ETHERNET_ID);
    
    DefaultRawSessionConfig config=new DefaultRawSessionConfig(addr1);    
    RawIoAcceptor service=new RawIoAcceptor(config);
    service.setHandler(......);
    ......
    
    service.bind();
    
    
# IoConnector for a NIC 
    EthAddress addr2=EthAddress.get_addr_by_ip("10.10.10.2");        
    addr.setEthType(0x0800);        
    addr.setFrameType(JProtocol.ETHERNET_ID);
        
    DefaultRawSessionConfig config=new DefaultRawSessionConfig(addr2);
    RawIoConnector connector=new RawIoConnector(config);
    connector.setHandler(......);
    ......
    
    connector.connect(addr1);
    
