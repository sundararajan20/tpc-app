package org.onosproject.tpc.common;

public class SliceQoSEntry {
    private byte sliceId;
    private long pir;

    public SliceQoSEntry(byte sliceId, long pir)
    {
        this.sliceId = sliceId;
        this.pir = pir;
    }

    public byte getSliceId() { return this.sliceId; }

    public long getPir() { return this.pir; }

    @Override
    public String toString() {
        return String.format(
                "SliceQoSEntry: sliceId=%s, pir=%s",
                sliceId, pir);
    }
}
