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

import com.google.common.collect.Lists;
import org.onlab.packet.Ethernet;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.meter.*;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.tpc.common.CheckerSliceIdEntry;
import org.onosproject.tpc.common.ExfiltrationAttackEntry;
import org.onosproject.tpc.common.SliceQoSEntry;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static org.onosproject.tpc.AppConstants.HIGH_FLOW_RULE_PRIORITY;
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
    private DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MeterService meterService;

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

        flowRuleService.removeFlowRulesById(appId);
        for (Device device: deviceService.getAvailableDevices()) {
            meterService.purgeMeters(device.id(), appId);
        }

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
        for (Device device: deviceService.getAvailableDevices()) {
            meterService.purgeMeters(device.id(), appId);
        }
    }

    @Override
    public void turnOnChecking() {
        log.info("Received turnOnChecking request");

        installAclPuntRules();

        List<FlowRule> turnOnCheckingRules = new ArrayList<>();
        for (Device device: deviceService.getAvailableDevices()) {
            String tableIdIsoCheck = "FabricEgress.checker_control.tb_should_check_iso";
            String tableIdQoSCheck = "FabricEgress.checker_control.tb_should_check_qos";
            PiMatchFieldId ETH_IS_VALID = PiMatchFieldId.of("eth_is_valid");
            PiActionId piActionIdCheckIso = PiActionId.of("FabricEgress.checker_control.check_iso");
            PiActionId piActionIdCheckQoS = PiActionId.of("FabricEgress.checker_control.check_qos");

            PiCriterion match1 = PiCriterion.builder()
                    .matchExact(ETH_IS_VALID, 1)
                    .build();

            PiAction action1 = PiAction.builder()
                    .withId(piActionIdCheckIso)
                    .build();

            turnOnCheckingRules.add(buildFlowRule(device.id(), appId, tableIdIsoCheck, match1, action1, MEDIUM_FLOW_RULE_PRIORITY));

            PiCriterion match2 = PiCriterion.builder()
                    .matchExact(ETH_IS_VALID, 1)
                    .build();

            PiAction action2 = PiAction.builder()
                    .withId(piActionIdCheckQoS)
                    .build();

            turnOnCheckingRules.add(buildFlowRule(device.id(), appId, tableIdQoSCheck, match2, action2, MEDIUM_FLOW_RULE_PRIORITY));
        }

        flowRuleService.applyFlowRules(turnOnCheckingRules.toArray(new FlowRule[turnOnCheckingRules.size()]));
    }

    @Override
    public void turnOffChecking() {
        log.info("Received turnOffChecking request");

        List<FlowRule> turnOnCheckingRules = new ArrayList<>();
        for (Device device: deviceService.getAvailableDevices()) {
            String tableIdIsoCheck = "FabricEgress.checker_control.tb_should_check_iso";
            String tableIdQoSCheck = "FabricEgress.checker_control.tb_should_check_qos";
            PiMatchFieldId ETH_IS_VALID = PiMatchFieldId.of("eth_is_valid");
            PiActionId piActionIdCheckIso = PiActionId.of("FabricEgress.checker_control.check_iso");
            PiActionId piActionIdCheckQoS = PiActionId.of("FabricEgress.checker_control.check_qos");

            PiCriterion match1 = PiCriterion.builder()
                    .matchExact(ETH_IS_VALID, 1)
                    .build();

            PiAction action1 = PiAction.builder()
                    .withId(piActionIdCheckIso)
                    .build();

            turnOnCheckingRules.add(buildFlowRule(device.id(), appId, tableIdIsoCheck, match1, action1, MEDIUM_FLOW_RULE_PRIORITY));

            PiCriterion match2 = PiCriterion.builder()
                    .matchExact(ETH_IS_VALID, 1)
                    .build();

            PiAction action2 = PiAction.builder()
                    .withId(piActionIdCheckQoS)
                    .build();

            turnOnCheckingRules.add(buildFlowRule(device.id(), appId, tableIdQoSCheck, match2, action2, MEDIUM_FLOW_RULE_PRIORITY));
        }

        flowRuleService.removeFlowRules(turnOnCheckingRules.toArray(new FlowRule[turnOnCheckingRules.size()]));
    }

    @Override
    public void postCheckerSliceIdEntries(List<CheckerSliceIdEntry> checkerSliceIdEntries) {
        log.info("Received checkerSliceIdEntries: {}", checkerSliceIdEntries);
        handleCheckerSliceIdEntries(checkerSliceIdEntries);
    }

    @Override
    public void postSliceQoSEntries(List<SliceQoSEntry> sliceQoSEntries) {
        log.info("Received sliceQoSEntries: {}", sliceQoSEntries);
        handleSliceQosEntries(sliceQoSEntries);
    }

    public void handleSliceQosEntries(List<SliceQoSEntry> sliceQoSEntries) {
        for (SliceQoSEntry sliceQoSEntry: sliceQoSEntries) {
            handleSliceQoSEntry(sliceQoSEntry);
        }
    }

    public void handleSliceQoSEntry(SliceQoSEntry sliceQoSEntry) {
        List<MeterRequest> sliceQoSEntryMeterRequests = new ArrayList<>();

        sliceQoSEntryMeterRequests.addAll(getFlowRulesForSliceQoSEntry(sliceQoSEntry));

        for (MeterRequest meterRequest: sliceQoSEntryMeterRequests) {
            meterService.submit(meterRequest);
        }
    }

    public List<MeterRequest> getFlowRulesForSliceQoSEntry(SliceQoSEntry sliceQoSEntry) {
        List<MeterRequest> meterRequests = new ArrayList<>();

        for (Device device: deviceService.getAvailableDevices()) {
            MeterRequest.Builder meterRequest = DefaultMeterRequest.builder()
                    .forDevice(device.id())
                    .fromApp(appId)
                    .withScope(MeterScope.of("FabricEgress.checker_control.slice_meter"))
                    .withUnit(Meter.Unit.BYTES_PER_SEC)
                    .withIndex((long) sliceQoSEntry.getSliceId());

            Collection<Band> bands = Lists.newArrayList();
            // Add rate 1
            bands.add(DefaultBand.builder()
                    .ofType(Band.Type.MARK_YELLOW)
                    .withRate(0).burstSize(0)
                    .build());

            // Add rate 2
            bands.add(DefaultBand.builder()
                    .ofType(Band.Type.MARK_RED)
                    .withRate(sliceQoSEntry.getPir() / 8).burstSize(1500)
                    .build());

            meterRequest.withBands(bands);
            meterRequests.add(meterRequest.add());
        }

        return meterRequests;
    }

    public void handleCheckerSliceIdEntries(List<CheckerSliceIdEntry> checkerSliceIdEntries) {
        for (CheckerSliceIdEntry checkerSliceIdEntry: checkerSliceIdEntries) {
            handleCheckerSliceIdEntry(checkerSliceIdEntry);
        }
    }

    public void handleCheckerSliceIdEntry(CheckerSliceIdEntry checkerSliceIdEntry) {
        List<FlowRule> checkerSliceIdEntryFlowRules = new ArrayList<>();

        checkerSliceIdEntryFlowRules.addAll(getFlowRulesForCheckerSliceIdEntry(checkerSliceIdEntry));

        flowRuleService.applyFlowRules(checkerSliceIdEntryFlowRules.toArray(new FlowRule[checkerSliceIdEntryFlowRules.size()]));
    }

    public List<FlowRule> getFlowRulesForCheckerSliceIdEntry(CheckerSliceIdEntry checkerSliceIdEntry) {
        List<FlowRule> flowRules = new ArrayList<>();

        String tableIdIngressLookup = "FabricIngress.init_control.tb_lookup_static_slices";
        String tableIdEgressLookup = "FabricEgress.checker_control.tb_lookup_static_slices";
        PiMatchFieldId HDR_IG_PORT = PiMatchFieldId.of("ig_port");
        PiMatchFieldId HDR_EG_PORT = PiMatchFieldId.of("eg_port");
        PiActionId piActionIdIngressSliceLookup = PiActionId.of("FabricIngress.init_control.lookup_key_in_port_in_slices");
        PiActionId piActionIdEgressSliceLookup = PiActionId.of("FabricEgress.checker_control.lookup_key_eg_port_in_slices");
        PiActionParamId IG_SLICE_ID = PiActionParamId.of("ig_slice_id");
        PiActionParamId EG_SLICE_ID = PiActionParamId.of("eg_slice_id");

        PiCriterion match1 = PiCriterion.builder()
                .matchExact(HDR_IG_PORT, checkerSliceIdEntry.getPortNumber().toLong())
                .build();

        PiAction action1 = PiAction.builder()
                .withId(piActionIdIngressSliceLookup)
                .withParameter(new PiActionParam(IG_SLICE_ID, checkerSliceIdEntry.getSliceId()))
                .build();

        flowRules.add(buildFlowRule(DeviceId.deviceId(checkerSliceIdEntry.getDeviceId()), appId, tableIdIngressLookup, match1, action1, MEDIUM_FLOW_RULE_PRIORITY));

        PiCriterion match2 = PiCriterion.builder()
                .matchExact(HDR_EG_PORT, checkerSliceIdEntry.getPortNumber().toLong())
                .build();

        PiAction action2 = PiAction.builder()
                .withId(piActionIdEgressSliceLookup)
                .withParameter(new PiActionParam(EG_SLICE_ID, checkerSliceIdEntry.getSliceId()))
                .build();

        flowRules.add(buildFlowRule(DeviceId.deviceId(checkerSliceIdEntry.getDeviceId()), appId, tableIdEgressLookup, match2, action2, MEDIUM_FLOW_RULE_PRIORITY));

        String tableIdCheckFirstHop = "FabricIngress.init_control.tb_check_first_hop";
        String tableIdCheckLastHop = "FabricEgress.checker_control.tb_check_last_hop";
        PiActionId piActionIdCheckFirstHop = PiActionId.of("FabricIngress.init_control.set_first_hop");
        PiActionId piActionIdCheckLastHop = PiActionId.of("FabricEgress.checker_control.set_last_hop");

        PiCriterion match3 = PiCriterion.builder()
                .matchExact(HDR_IG_PORT, checkerSliceIdEntry.getPortNumber().toLong())
                .build();

        PiAction action3 = PiAction.builder()
                .withId(piActionIdCheckFirstHop)
                .build();

        flowRules.add(buildFlowRule(DeviceId.deviceId(checkerSliceIdEntry.getDeviceId()), appId, tableIdCheckFirstHop, match3, action3, MEDIUM_FLOW_RULE_PRIORITY));

        PiCriterion match4 = PiCriterion.builder()
                .matchExact(HDR_EG_PORT, checkerSliceIdEntry.getPortNumber().toLong())
                .build();

        PiAction action4 = PiAction.builder()
                .withId(piActionIdCheckLastHop)
                .build();

        flowRules.add(buildFlowRule(DeviceId.deviceId(checkerSliceIdEntry.getDeviceId()), appId, tableIdCheckLastHop, match4, action4, MEDIUM_FLOW_RULE_PRIORITY));

        return flowRules;
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

    public void installAclPuntRules()
    {
        List<FlowRule> puntRules = new ArrayList<>();
        for (Device device: deviceService.getAvailableDevices()) {
            FlowRule puntRule = failedPacketsAclRule(device.id());
            if (mastershipService.isLocalMaster(device.id())) {
                puntRules.add(puntRule);
            }
        }

        flowRuleService.applyFlowRules(puntRules.toArray(new FlowRule[puntRules.size()]));
    }

    public FlowRule failedPacketsAclRule(DeviceId deviceId)
    {
        String tableId = "FabricIngress.acl.acl";
        PiMatchFieldId HDR_ETH_TYPE = PiMatchFieldId.of("eth_type");
        PiActionId piActionId = PiActionId.of("FabricIngress.acl.punt_to_cpu");

        PiCriterion match = PiCriterion.builder()
                .matchTernary(HDR_ETH_TYPE, CHECKER_REPORT_ETH_TYPE, CHECKER_REPORT_ETH_MASK)
                .build();

        PiAction action = PiAction.builder()
                .withId(piActionId)
                .build();

        return buildFlowRule(deviceId, appId, tableId, match, action, HIGH_FLOW_RULE_PRIORITY);
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
