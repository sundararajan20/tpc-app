/*
 * Copyright 2022-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.tpc;

import org.onlab.packet.Ethernet;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.tpc.common.ExfiltrationAttackEntry;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Dictionary;
import java.util.List;
import java.util.Properties;

import static org.onlab.util.Tools.get;
import static org.onosproject.tpc.AppConstants.MEDIUM_FLOW_RULE_PRIORITY;
import static org.onosproject.tpc.common.Utils.buildFlowRule;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true, enabled = true)
public class TPCComponent implements TPCService {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private ApplicationId appId;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MainComponent mainComponent;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    private static short CHECKER_REPORT_ETH_TYPE = (short) 0x5678;
    private static short CHECKER_REPORT_ETH_MASK = (short) 0xFFFF;

    private final InternalPacketProcessor packetProcessor = new InternalPacketProcessor();

    @Activate
    protected void activate() {
        appId = mainComponent.getAppId();

        packetService.addProcessor(packetProcessor, PacketProcessor.advisor(0));

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(packetProcessor);

        log.info("Stopped");
    }

    @Override
    public void postExfiltrationAttackEntries(List<ExfiltrationAttackEntry> attackEntries) {
        log.info("Received attack entries: {}", attackEntries);
        handleAttackEntries(attackEntries);
    }

    @Override
    public void flushFlowRules() {
        log.info("Received flush request");
        flowRuleService.removeFlowRulesById(appId);
    }

    public void handleAttackEntries(List<ExfiltrationAttackEntry> attackEntries) {
        for (ExfiltrationAttackEntry attackEntry: attackEntries) {
            handleAttackEntry(attackEntry);
        }
    }

    public void handleAttackEntry(ExfiltrationAttackEntry attackEntry) {
        List<FlowRule> attackEntryFlowRules = new ArrayList<>();

        attackEntryFlowRules.addAll(getFlowRulesForAttackEntry(attackEntry));

        flowRuleService.applyFlowRules(attackEntryFlowRules.toArray(new FlowRule[attackEntryFlowRules.size()]));
    }

    public List<FlowRule> getFlowRulesForAttackEntry(ExfiltrationAttackEntry attackEntry) {
        List<FlowRule> flowRules = new ArrayList<>();

        String tableId = "FabricIngress.attack_ingress.attack";
        PiMatchFieldId HDR_IPV4_SRC = PiMatchFieldId.of("ipv4_src");
        PiMatchFieldId HDR_IPV4_DST = PiMatchFieldId.of("ipv4_dst");
        PiActionId piActionIdExfiltrate = PiActionId.of("FabricIngress.attack_ingress.add_metadata_and_duplicate");
        PiActionParamId IPV4_SRC_REWRITTEN = PiActionParamId.of("ipv4_src_addr");
        PiActionParamId IPV4_DST_REWRITTEN = PiActionParamId.of("ipv4_dst_addr");

        PiCriterion match = PiCriterion.builder()
                .matchExact(HDR_IPV4_SRC, attackEntry.getSrcAddress().toOctets())
                .matchExact(HDR_IPV4_DST, attackEntry.getDstAddress().toOctets())
                .build();

        PiAction action = PiAction.builder()
                .withId(piActionIdExfiltrate)
                .withParameter(new PiActionParam(IPV4_SRC_REWRITTEN, attackEntry.getSrcAddressRewritten().toOctets()))
                .withParameter(new PiActionParam(IPV4_DST_REWRITTEN, attackEntry.getDstAddressRewritten().toOctets()))
                .build();

        flowRules.add(buildFlowRule(DeviceId.deviceId(attackEntry.getDeviceId()), appId, tableId, match, action, MEDIUM_FLOW_RULE_PRIORITY));

        return flowRules;
    }

    /**
     * Processes incoming packets.
     */
    private class InternalPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            Ethernet eth = context.inPacket().parsed();
            if (eth.getEtherType() == CHECKER_REPORT_ETH_TYPE) {
                log.info("Packet received from checker on device {}!", context.inPacket().receivedFrom());
                context.block();
            }
        }
    }
}
