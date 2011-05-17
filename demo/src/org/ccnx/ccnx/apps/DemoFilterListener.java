package org.ccnx.ccn.apps.demoserver;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.ccnx.ccn.CCNFilterListener;
import org.ccnx.ccn.CCNHandle;
import org.ccnx.ccn.config.ConfigurationException;
import org.ccnx.ccn.impl.support.Log;
import org.ccnx.ccn.io.CCNFileOutputStream;
import org.ccnx.ccn.profiles.CommandMarker;
import org.ccnx.ccn.profiles.SegmentationProfile;
import org.ccnx.ccn.profiles.VersioningProfile;
import org.ccnx.ccn.profiles.metadata.MetadataProfile;
import org.ccnx.ccn.profiles.nameenum.NameEnumerationResponse;
import org.ccnx.ccn.profiles.nameenum.NameEnumerationResponse.NameEnumerationResponseMessage;
import org.ccnx.ccn.profiles.nameenum.NameEnumerationResponse.NameEnumerationResponseMessage.NameEnumerationResponseMessageObject;
import org.ccnx.ccn.profiles.security.KeyProfile;
import org.ccnx.ccn.protocol.CCNTime;
import org.ccnx.ccn.protocol.ContentName;
import org.ccnx.ccn.protocol.Exclude;
import org.ccnx.ccn.protocol.ExcludeComponent;
import org.ccnx.ccn.protocol.Interest;
import org.ccnx.ccn.protocol.MalformedContentNameStringException;

public class DemoFilterListener implements CCNFilterListener {

    protected ContentName _namespace;
    protected String _namespacestr;

    protected CCNHandle _handle;
    protected ContentName _serverName = null;

    public DemoFilterListener(String mountpoint, CCNHandle handle) throws MalformedContentNameStringException {
        _namespace = ContentName.fromURI(mountpoint);
        _namespacestr = mountpoint;

        _handle = handle;

        _serverName = KeyProfile.keyName(null, _handle.keyManager().getDefaultKeyID());
    }

    public void start() throws IOException {
        Log.info("Listening on: " + _namespacestr + "...");
        _handle.registerFilter(_namespace,this);
    }

    public boolean handleInterest(Interest interest) {
        Log.info("DemoServer got new interest: {0}", interest);
        return true;
    }
}
