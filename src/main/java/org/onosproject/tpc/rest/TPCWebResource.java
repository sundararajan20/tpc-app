package org.onosproject.tpc.rest;

import com.fasterxml.jackson.databind.JsonNode;
import org.onlab.packet.Ip4Address;
import org.onosproject.rest.AbstractWebResource;
import org.onosproject.tpc.TPCService;
import org.onosproject.tpc.common.ExfiltrationAttackEntry;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static org.onlab.util.Tools.readTreeFromStream;

@Path("tpc")
public class TPCWebResource extends AbstractWebResource {
    @GET
    @Path("flush")
    public Response flushFlowRules() {
        get(TPCService.class).flushFlowRules();
        return Response.noContent().build();
    }

    /**
     * Post attack entry.
     *
     * @return 204 NoContent
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("add_attack")
    public Response postSourceRewriteAttack(InputStream stream) {
        List<ExfiltrationAttackEntry> attackEntries = jsonToAttackEntries(stream);
        get(TPCService.class).postExfiltrationAttackEntries(attackEntries);
        return Response.noContent().build();
    }

    private List<ExfiltrationAttackEntry> jsonToAttackEntries(InputStream stream) throws IllegalArgumentException {
        List<ExfiltrationAttackEntry> attackEntries = new ArrayList<>();

        JsonNode node;
        try {
            node = readTreeFromStream(mapper(), stream);
        } catch (IOException e) {
            throw new IllegalArgumentException("Unable to parse add request", e);
        }

        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            JsonNode subNode = field.getValue();

            String deviceIdStr = subNode.path("deviceId").asText(null);
            String srcAddressStr = subNode.path("srcAddress").asText(null);
            String dstAddressStr = subNode.path("dstAddress").asText(null);
            String srcAddressRewrittenStr = subNode.path("srcAddressRewritten").asText(null);
            String dstAddressRewrittenStr = subNode.path("dstAddressRewritten").asText(null);

            if (deviceIdStr != null && srcAddressStr != null && dstAddressStr != null && srcAddressRewrittenStr != null && dstAddressRewrittenStr != null) {
                Ip4Address srcIp4Address = Ip4Address.valueOf(srcAddressStr);
                Ip4Address dstIp4Address = Ip4Address.valueOf(dstAddressStr);
                Ip4Address srcIp4AddressRewritten = Ip4Address.valueOf(srcAddressRewrittenStr);
                Ip4Address dstIp4AddressRewritten = Ip4Address.valueOf(dstAddressRewrittenStr);

                attackEntries.add(new ExfiltrationAttackEntry(deviceIdStr, srcIp4Address, dstIp4Address, srcIp4AddressRewritten, dstIp4AddressRewritten));
            }
        }

        return attackEntries;
    }
}
