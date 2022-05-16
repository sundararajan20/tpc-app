package org.onosproject.tpc;

import org.onosproject.tpc.common.CheckerSliceIdEntry;
import org.onosproject.tpc.common.ExfiltrationAttackEntry;
import org.onosproject.tpc.common.SliceQoSEntry;

import java.util.List;

public interface TPCService {
    void postExfiltrationAttackEntries(List<ExfiltrationAttackEntry> attackEntries);

    void flushFlowRules();

    void postCheckerSliceIdEntries(List<CheckerSliceIdEntry> checkerSliceIdEntries);

    void postSliceQoSEntries(List<SliceQoSEntry> sliceQoSEntries);

    void turnOnChecking();
}
