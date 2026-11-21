// SPDX-License-Identifier: Apache-2.0
package kioskvoip.intercom;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * SPIKE (outgoing calls, option A): one contact that the kiosk lists as an intercom peer.
 *
 * Announces {@code _kiosk-satellite._tcp} over mDNS under its own instance and host name (never the kiosk's, which
 * KS would flag as a host clash), serves {@code GET /api/intercom/identity}, and takes {@code POST /api/intercom/call}
 * when someone on the kiosk calls the contact. For the spike it only logs the call, replies {@code ringing} and
 * declines after a few seconds so the call card closes. No SIP yet.
 */
public final class VirtualPeer implements Closeable {
    public interface Listener {
        /** A kiosk called this contact. Runs on a server thread. */
        void onCall(String callId, String fromName, String fromAddress);
    }

    private static final InetSocketAddress MDNS = new InetSocketAddress("224.0.0.251", 5353);
    private static final String SERVICE = "_kiosk-satellite._tcp.local";
    private static final int TTL = 120;
    private static final long ANNOUNCE_MS = 20_000;
    private static final long DECLINE_AFTER_MS = 6_000;

    private final String id, name, version, key;
    private final Consumer<String> log;
    private final Listener listener;
    private final ServerSocket server;
    private final MulticastSocket mdns;
    private final Inet4Address lan;
    private final Map<String, Boolean> usedNonces = new LinkedHashMap<String, Boolean>() {
        @Override protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) { return size() > 256; }
    };
    private volatile boolean open = true;

    public VirtualPeer(String id, String name, String version, String key, Listener listener, Consumer<String> log)
            throws IOException {
        this.id = id;
        this.name = name;
        this.version = version;
        this.key = key;
        this.listener = listener;
        this.log = log;
        NetworkInterface[] nic = new NetworkInterface[1];
        lan = lanAddress(nic);
        if (lan == null) throw new IOException("no LAN IPv4 address");
        // The kiosk calls the address in the A record, so this one listens on the LAN, not on loopback.
        server = new ServerSocket(0, 10, InetAddress.getByName("0.0.0.0"));
        mdns = new MulticastSocket(0);
        mdns.setTimeToLive(255);
        mdns.setLoopbackMode(false); // false = loopback ON (Java's inverted flag): the kiosk on this device must hear it
        mdns.setNetworkInterface(nic[0]);
        Thread accept = new Thread(this::acceptLoop, "virtual-peer-http");
        accept.setDaemon(true);
        accept.start();
        Thread announce = new Thread(this::announceLoop, "virtual-peer-mdns");
        announce.setDaemon(true);
        announce.start();
        log.accept("spike: contact '" + name + "' (id " + id + ") on " + lan.getHostAddress() + ":" + server.getLocalPort());
    }

    public int port() { return server.getLocalPort(); }

    private String instance() { return "kp-" + id + "." + SERVICE; }

    private String hostName() { return "kp-" + id + ".local"; }

    @Override public void close() {
        open = false;
        try { send(0); } catch (IOException ignored) { } // goodbye: the kiosk drops the peer at once
        mdns.close();
        try { server.close(); } catch (IOException ignored) { }
    }

    // ── mDNS ────────────────────────────────────────────────────────────

    private void announceLoop() {
        while (open) {
            try {
                send(TTL);
            } catch (IOException failure) {
                if (open) log.accept("spike: mDNS announce failed: " + failure.getMessage());
            }
            try { Thread.sleep(ANNOUNCE_MS); } catch (InterruptedException stop) { return; }
        }
    }

    private void send(int ttl) throws IOException {
        byte[] packet = announcement(ttl);
        mdns.send(new DatagramPacket(packet, packet.length, MDNS));
    }

    byte[] announcement(int ttl) {
        Dns w = new Dns();
        w.u16(0); w.u16(0x8400); w.u16(0); w.u16(4); w.u16(0); w.u16(0);
        // PTR service → instance
        w.name(SERVICE); w.u16(12); w.u16(1); w.u32(ttl);
        int at = w.mark(); w.name(instance()); w.fill(at);
        // SRV instance → host:port (cache flush)
        w.name(instance()); w.u16(33); w.u16(0x8001); w.u32(ttl);
        at = w.mark(); w.u16(0); w.u16(0); w.u16(port()); w.name(hostName()); w.fill(at);
        // TXT
        w.name(instance()); w.u16(16); w.u16(0x8001); w.u32(ttl);
        at = w.mark();
        for (String entry : new String[] {"id=" + id, "name=" + name, "version=" + version, "port=" + port(), "host=kp-" + id}) {
            byte[] b = entry.getBytes(StandardCharsets.UTF_8);
            w.u8(b.length); w.bytes(b);
        }
        w.fill(at);
        // A host → LAN address
        w.name(hostName()); w.u16(1); w.u16(0x8001); w.u32(ttl);
        at = w.mark(); w.bytes(lan.getAddress()); w.fill(at);
        return w.done();
    }

    private static Inet4Address lanAddress(NetworkInterface[] chosen) throws IOException {
        for (NetworkInterface nic : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            if (!nic.isUp() || nic.isLoopback() || !nic.supportsMulticast()) continue;
            for (InetAddress a : Collections.list(nic.getInetAddresses())) {
                if (a instanceof Inet4Address && a.isSiteLocalAddress()) {
                    chosen[0] = nic;
                    return (Inet4Address) a;
                }
            }
        }
        return null;
    }

    /** Minimal DNS writer, no name compression. */
    static final class Dns {
        private byte[] buf = new byte[512];
        private int pos;

        void u8(int v) { grow(1); buf[pos++] = (byte) v; }
        void u16(int v) { u8(v >> 8); u8(v); }
        void u32(int v) { u16(v >>> 16); u16(v & 0xffff); }
        void bytes(byte[] b) { grow(b.length); System.arraycopy(b, 0, buf, pos, b.length); pos += b.length; }
        void name(String n) {
            for (String label : n.split("\\.")) {
                byte[] b = label.getBytes(StandardCharsets.UTF_8);
                u8(b.length); bytes(b);
            }
            u8(0);
        }
        /** Reserves the rdlength field and returns where the data starts. */
        int mark() { u16(0); return pos; }
        void fill(int start) { int len = pos - start; buf[start - 2] = (byte) (len >> 8); buf[start - 1] = (byte) len; }
        byte[] done() { byte[] out = new byte[pos]; System.arraycopy(buf, 0, out, 0, pos); return out; }
        private void grow(int n) { if (pos + n > buf.length) buf = java.util.Arrays.copyOf(buf, Math.max(buf.length * 2, pos + n)); }
    }

    // ── HTTP ────────────────────────────────────────────────────────────

    private void acceptLoop() {
        while (!server.isClosed()) {
            try {
                Socket s = server.accept();
                Thread h = new Thread(() -> handle(s), "virtual-peer-conn");
                h.setDaemon(true);
                h.start();
            } catch (IOException closed) {
                return;
            }
        }
    }

    private void handle(Socket socket) {
        try (Socket s = socket) {
            s.setSoTimeout(3000);
            InputStream in = new BufferedInputStream(s.getInputStream());
            OutputStream out = s.getOutputStream();
            String[] request = Http.line(in).split(" ");
            Map<String, String> headers = Http.headers(in);
            int length = Integer.parseInt(headers.getOrDefault("content-length", "0"));
            if (length < 0 || length > 16384) { reply(out, 413, "{}"); return; }
            String body = new String(Http.exactly(in, length), StandardCharsets.UTF_8);
            if (request.length < 2) { reply(out, 400, "{}"); return; }
            String remote = s.getInetAddress().getHostAddress();
            if (request[0].equals("GET") && request[1].equals("/api/intercom/identity")) {
                Map<String, Object> endpoint = new LinkedHashMap<>();
                endpoint.put("port", (long) port());
                endpoint.put("tls", false);
                Map<String, Object> identity = new LinkedHashMap<>();
                identity.put("id", id);
                identity.put("name", name);
                identity.put("version", version);
                identity.put("enabled", true);
                identity.put("endpoint", endpoint);
                identity.put("key", IntercomAuth.digest(key));
                identity.put("dnd", false);
                identity.put("video", false);
                reply(out, 200, Json.write(identity));
                return;
            }
            if (request[0].equals("POST") && request[1].equals("/api/intercom/call")) {
                Map<String, Object> call = Json.object(body);
                Object callId = call.get("call");
                String bearer = headers.getOrDefault("authorization", "");
                if (!(callId instanceof String) || !bearer.startsWith("Bearer ")
                        || !validToken(bearer.substring(7), (String) callId)) {
                    log.accept("spike: call from " + remote + " refused (bad token)");
                    reply(out, 403, "{}");
                    return;
                }
                Object kind = call.get("kind");
                Object from = call.get("from");
                @SuppressWarnings("unchecked")
                Map<String, Object> f = from instanceof Map ? (Map<String, Object>) from : Collections.emptyMap();
                String fromName = String.valueOf(f.get("name"));
                String fromAddress = f.get("address") instanceof String ? (String) f.get("address") : remote;
                log.accept("spike: CALL kind=" + kind + " from '" + fromName + "' (" + fromAddress + ":" + f.get("port")
                    + ", seen from " + remote + "), actions=" + call.get("actions"));
                listener.onCall((String) callId, fromName, fromAddress);
                reply(out, 200, "{\"status\":\"ringing\"}");
                Object port = f.get("port");
                if (port instanceof Long) declineLater((String) callId, fromAddress, ((Long) port).intValue());
                return;
            }
            if (request[0].equals("POST") && request[1].startsWith("/api/intercom/call/")) {
                log.accept("spike: caller action " + body);
                reply(out, 200, "{\"ok\":true}");
                return;
            }
            log.accept("spike: " + request[0] + " " + request[1] + " from " + remote + " → 404");
            reply(out, 404, "{}");
        } catch (IOException | RuntimeException failure) {
            log.accept("spike: http: " + failure.getMessage());
        }
    }

    private void declineLater(String call, String host, int port) {
        Thread t = new Thread(() -> {
            try {
                Thread.sleep(DECLINE_AFTER_MS);
                Http.Response r = Http.request(host, port, "POST", "/api/intercom/call/" + call,
                    IntercomAuth.token(key, call, id), "{\"action\":\"decline\"}", 3000);
                log.accept("spike: sent decline → HTTP " + r.status);
            } catch (IOException | InterruptedException failure) {
                log.accept("spike: decline failed: " + failure.getMessage());
            }
        }, "virtual-peer-decline");
        t.setDaemon(true);
        t.start();
    }

    private boolean validToken(String token, String call) {
        int dot = token.indexOf('.');
        if (dot < 0) return false;
        String payload = token.substring(0, dot);
        byte[] given;
        try {
            given = B64.decodeUrl(token.substring(dot + 1));
        } catch (IllegalArgumentException bad) {
            return false;
        }
        if (!MessageDigest.isEqual(IntercomAuth.hmac(key, payload), given)) return false;
        Map<String, Object> claims;
        try {
            claims = Json.object(new String(B64.decodeUrl(payload), StandardCharsets.UTF_8));
        } catch (IllegalArgumentException bad) {
            return false;
        }
        if (!call.equals(claims.get("intercom")) || !(claims.get("exp") instanceof Long) || !(claims.get("n") instanceof String)) return false;
        if ((Long) claims.get("exp") < System.currentTimeMillis()) return false;
        synchronized (usedNonces) {
            return usedNonces.put((String) claims.get("n"), Boolean.TRUE) == null;
        }
    }

    private static void reply(OutputStream out, int status, String body) throws IOException {
        byte[] data = body.getBytes(StandardCharsets.UTF_8);
        out.write(("HTTP/1.1 " + status + " X\r\nContent-Type: application/json\r\nContent-Length: " + data.length
            + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(data);
        out.flush();
    }
}
