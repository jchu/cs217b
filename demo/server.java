package org.ccnx.ccn.apps.demoserver;

import java.io.IOException;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.logging.Level;

import org.ccnx.ccn.CCNHandle;
import org.ccnx.ccn.config.ConfigurationException;
import org.ccnx.ccn.config.UserConfiguration;
import org.ccnx.ccn.impl.CCNFlowControl.SaveType;
import org.ccnx.ccn.impl.support.Log;
import org.ccnx.ccn.io.content.CCNStringObject;
import org.ccnx.ccn.io.content.ContentEncodingException;
import org.ccnx.ccn.profiles.security.KeyProfile;
import org.ccnx.ccn.protocol.ContentName;
import org.ccnx.ccn.protocol.KeyLocator;
import org.ccnx.ccn.protocol.MalformedContentNameStringException;
import org.ccnx.ccn.protocol.PublisherPublicKeyDigest

public final class DemoServer {
    //public DemoServer(DemoServerCallback callback, String namespace) throws MalformedContentNameStringException {
    public DemoServer(String mountpoint) throws MalformedContentNameStringException {
        String namespace = mountpoint;
        _namespace = ContentName.fromURI(namespace);
        _namespaceStr = namespace;
    }

    public void setup() {
        UserConfiguration.setDefaultNamespacePrefix(_namespace.toString());

        CCNHandle readHandle = CCNHandle.open();
        CCNHandle writeHandle = CCNHandle.open();

        _readString = new CCNStringObject(_namespace, (String)null, SaveType.RAW, readHandle());
        _readString.updateInBackground(true);

        _writeString = new CCNStringObject(_namespace, (String)null, SaveType.RAW, readHandle());

        // Publish server public key
        String hostName = SystemConfiguration.getLocalHost();
        Log.info("*** Publishing host mountpoint: " + hostName);
        _writeHostName = new CCNStringObject(_namespace, hostName, SaveType.RAW , writeHandle);
        _writeHostName.save();
    }

    public void run() {
        setup();

        while(true) {
            System.out.print('.');
            
            if( _readString.isSave() ) {
                // Received an interest from a new client
                Log.info("[" + _readString.getVersion() + "] Received an interest from a new client");

                String publisher = _readString.getContentPublisher();


            }
        }
    }

    public static void usage() {
        System.err.println("usage: DemoServer <ccn mountpointURI>");
    }

    public static void main(String[] args) {
        if( args.length != 1 ) {
            usage();
            System.exit(-1);
        }
        DemoServer server;

        try {
            server = new DemoServer(args[0]);
            server.start();
        } catch (MalformedContentNameStringException e) {
            System.err.println("Not a valid ccn URI: " + args[0] + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    private final ContentName _namespace;
    private final String _namespaceStr;

    private CCNStringObject _readString;
    private CCNStringObject _writeString;
}


