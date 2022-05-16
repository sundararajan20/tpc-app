package org.onosproject.tpc.common;

import org.onosproject.net.PortNumber;

public class CheckerSliceIdEntry {
    private String deviceId;
    private PortNumber portNumber;
    private Byte sliceId;

    public CheckerSliceIdEntry(String deviceId, PortNumber portNumber, Byte sliceId)
    {
        this.deviceId = deviceId;
        this.portNumber = portNumber;
        this.sliceId = sliceId;
    }

    public String getDeviceId() { return this.deviceId; }

    public PortNumber getPortNumber() { return this.portNumber; }

    public byte getSliceId() { return this.sliceId; }

    @Override
    public String toString() {
        return String.format(
                "CheckerSliceIdEntry: deviceId=%s, portNumber=%s, sliceId=%s",
                deviceId, portNumber, sliceId);
    }
}
