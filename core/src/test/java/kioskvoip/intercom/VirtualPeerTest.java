// SPDX-License-Identifier: Apache-2.0
package kioskvoip.intercom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

class VirtualPeerTest {
    private static final String KEY = "test-key";

    private static VirtualPeer open(List<String> calls) {
        try {
            return new VirtualPeer("0123456789abcdef", "Test Telefon", "0.0-test", KEY,
                (call, from, address) -> calls.add(from), line -> { });
        } catch (java.io.IOException noLan) {
            Assumptions.assumeTrue(false, "no LAN address here: " + noLan.getMessage());
            return null;
        }
    }

    @Test void identityMatchesKiosksFormat() throws Exception {
        try (VirtualPeer peer = open(new ArrayList<>())) {
            Http.Response r = Http.request("127.0.0.1", peer.port(), "GET", "/api/intercom/identity", null, null, 2000);
            assertEquals(200, r.status);
            Map<String, Object> id = Json.object(r.body);
            assertEquals("0123456789abcdef", id.get("id"));
            assertEquals(IntercomAuth.digest(KEY), id.get("key"));
            assertEquals(true, id.get("enabled"));
            assertEquals((long) peer.port(), ((Map<?, ?>) id.get("endpoint")).get("port"));
        }
    }

    @Test void callWithValidTokenRings() throws Exception {
        List<String> calls = new ArrayList<>();
        try (VirtualPeer peer = open(calls)) {
            String body = "{\"call\":\"c1\",\"kind\":\"call\",\"from\":{\"id\":\"ffff\",\"name\":\"KS_Peter\"}}";
            Http.Response r = Http.request("127.0.0.1", peer.port(), "POST", "/api/intercom/call",
                IntercomAuth.token(KEY, "c1", "ffff"), body, 2000);
            assertEquals(200, r.status);
            assertEquals("ringing", Json.object(r.body).get("status"));
            assertEquals(List.of("KS_Peter"), calls);
            Http.Response bad = Http.request("127.0.0.1", peer.port(), "POST", "/api/intercom/call",
                IntercomAuth.token("other", "c2", "ffff"), body.replace("c1", "c2"), 2000);
            assertEquals(403, bad.status);
        }
    }

    @Test void announcementHasFourRecords() throws Exception {
        try (VirtualPeer peer = open(new ArrayList<>())) {
            byte[] p = peer.announcement(120);
            assertEquals(0x84, p[2] & 0xff);
            assertEquals(4, ((p[6] & 0xff) << 8) | (p[7] & 0xff));
            String text = new String(p, java.nio.charset.StandardCharsets.ISO_8859_1);
            assertTrue(text.contains("id=0123456789abcdef"));
            assertTrue(text.contains("kp-0123456789abcdef"));
        }
    }
}
