package org.onosproject.tpc;

import org.onosproject.tpc.common.ExfiltrationAttackEntry;

import java.util.List;

public interface TPCService {
    void postExfiltrationAttackEntries(List<ExfiltrationAttackEntry> attackEntries);

    void flushFlowRules();
}
