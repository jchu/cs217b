package org.ccnx.ccn.apps.demoserver;

import java.io.IOException;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.logging.Level;

import org.ccnx.ccn.CCNHandle;
import org.ccnx.ccn.config.ConfigurationException;
import org.ccnx.ccn.config.UserConfiguration;
import org.ccnx.ccn.config.SystemConfiguration;
import org.ccnx.ccn.impl.CCNFlowControl.SaveType;
import org.ccnx.ccn.impl.support.Log;
import org.ccnx.ccn.io.content.CCNStringObject;
import org.ccnx.ccn.io.content.ContentEncodingException;
import org.ccnx.ccn.profiles.security.KeyProfile;
import org.ccnx.ccn.protocol.ContentName;
import org.ccnx.ccn.protocol.KeyLocator;
import org.ccnx.ccn.protocol.MalformedContentNameStringException;
import org.ccnx.ccn.protocol.PublisherPublicKeyDigest;

import org.ccnx.ccn.apps.demoserver.DemoFilterListener;

public final class DemoServer implements Runnable {
    //public DemoServer(DemoServerCallback callback, String namespace) throws MalformedContentNameStringException {
    public DemoServer(String mountpoint) throws MalformedContentNameStringException {
        String namespace = mountpoint;
        _namespace = ContentName.fromURI(namespace);
        _namespaceStr = namespace;

        _thd = new Thread(this,"DemoServer");
    }

    public void setup() throws MalformedContentNameStringException, IOException, ConfigurationException {
        UserConfiguration.setDefaultNamespacePrefix(_namespace.toString());

        _ccnHandle = CCNHandle.open();

        _writeString = new CCNStringObject(_namespace, (String)null, SaveType.RAW, _ccnHandle);

        // Publish server public key
        String hostName = SystemConfiguration.getLocalHost();
        Log.info("*** Publishing host mountpoint: " + hostName);
        CCNStringObject _writeHostName = new CCNStringObject(_namespace, hostName, SaveType.RAW , _ccnHandle);
        _writeHostName.save();

        _readString = new CCNStringObject(_namespace, (String)null, SaveType.RAW, _ccnHandle);
        _readString.updateInBackground(true);

        _listener = new DemoFilterListener(_namespaceStr,_ccnHandle);
        _ccnHandle.registerFilter(_namespace,_listener);
    }

    public void run() {
        while(true) {
            System.out.print('.');
            
            /*
            if( _readString.isSaved() ) {
                // Received an interest from a new client
                Log.info("[" + _readString.getVersion() + "] Received an interest from a new client");

                PublisherPublicKeyDigest publisher = _readString.getContentPublisher();


            }
            */
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
        } catch (ConfigurationException e) {
            System.err.println("Configuration exception running ccnChat: " + e.getMessage());
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("IOException handling chat messages: " + e.getMessage());
            e.printStackTrace();
        }
    }

    protected void start() throws ConfigurationException, MalformedContentNameStringException, IOException {
        _thd.start();
        setup();
        run();
    }

    private final Thread _thd;

    private final ContentName _namespace;
    private final String _namespaceStr;

    private CCNStringObject _readString;
    private CCNStringObject _writeString;

    private CCNHandle _ccnHandle;

    private DemoFilterListener _listener;
}


