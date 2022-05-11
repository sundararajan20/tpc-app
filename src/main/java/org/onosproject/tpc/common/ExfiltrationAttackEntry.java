package org.onosproject.tpc.common;

import org.onlab.packet.Ip4Address;

public class ExfiltrationAttackEntry {
    private String deviceId;
    private Ip4Address srcAddress, dstAddress, srcAddressRewritten, dstAddressRewritten;

    public ExfiltrationAttackEntry(String deviceId, Ip4Address srcAddress, Ip4Address dstAddress, Ip4Address srcAddressRewritten, Ip4Address dstAddressRewritten)
    {
        this.deviceId = deviceId;
        this.srcAddress = srcAddress;
        this.dstAddress = dstAddress;
        this.srcAddressRewritten = srcAddressRewritten;
        this.dstAddressRewritten = dstAddressRewritten;
    }

    public String getDeviceId() { return this.deviceId; }

    public Ip4Address getSrcAddress() { return this.srcAddress; }

    public Ip4Address getDstAddress() { return this.dstAddress; }

    public Ip4Address getSrcAddressRewritten() { return this.srcAddressRewritten; }

    public Ip4Address getDstAddressRewritten() { return this.dstAddressRewritten; }

    @Override
    public String toString() {
        return String.format(
                "AttackEntry: deviceId=%s, srcAddress=%s, dstAddress=%s, srcAddressRewritten=%s, dstAddressRewritten=%s",
                deviceId, srcAddress, dstAddress, srcAddressRewritten, dstAddressRewritten);
    }
}
