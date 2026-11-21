// SPDX-License-Identifier: Apache-2.0
package kioskvoip.plugin;

import java.util.Map;
import kioskvoip.intercom.VirtualPeer;
import me.jxl.kiosk.plugins.KioskPlugin;
import me.jxl.kiosk.plugins.PluginHost;

/** SPIKE (outgoing calls, option A): announces one test contact as an intercom peer. Runs beside Kiosk Phone. */
public final class SpikePlugin implements KioskPlugin {
    private static final String VERSION = "0.0.1";
    private PluginHost host;
    private VirtualPeer contact;
    private Map<String, Object> applied;

    @Override public synchronized void start(PluginHost host, Map<String, Object> settings) {
        this.host = host;
        host.publishTextSensor("spike_call", "Spike call", "none yet");
        open(settings);
    }

    @Override public synchronized void configure(Map<String, Object> settings) {
        if (settings.equals(applied)) return;
        close();
        open(settings);
    }

    @Override public void execute(String command, Map<String, Object> arguments) { }

    @Override public void onEvent(String event, Map<String, Object> payload) { }

    @Override public synchronized void stop() {
        close();
        host = null;
    }

    private void open(Map<String, Object> s) {
        applied = s;
        Object k = s.get("intercomKey");
        String key = k instanceof String ? ((String) k).trim() : "";
        if (key.isEmpty()) {
            host.status("No intercom key configured", true);
            return;
        }
        try {
            contact = new VirtualPeer("5e1f7e57c0ffee01", "Test Telefon", VERSION, key, (call, from, address) -> {
                PluginHost current = host;
                if (current != null) current.publishTextSensor("spike_call", "Spike call", from + " → Test Telefon");
            }, host::log);
            host.status("Announcing 'Test Telefon' on port " + contact.port(), false);
        } catch (java.io.IOException failure) {
            host.status("Test contact off: " + failure.getMessage(), true);
        }
    }

    private void close() {
        VirtualPeer c = contact;
        contact = null;
        if (c != null) c.close();
    }
}
