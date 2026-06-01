package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import javax.swing.AbstractAction;
import javax.swing.AbstractCellEditor;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTable;
import javax.swing.JToolBar;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.event.ChangeListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Burp extension tab that scores proxy-history and site-map entries on their
 * suitability as request-smuggling probe targets. The actual scoring lives in
 * {@link SmuggleTargetScorer} which has no Burp dependency and is unit-tested
 * via the independent test source set.
 *
 * <p>The Tab class itself is a thin presentation layer: it adapts Montoya
 * data to the pure DTOs, runs the scorer off the EDT, and routes launch
 * actions back into existing Burp tooling.</p>
 */
public class SmuggleTargetTab {

    static final String TAB_TITLE = "Smuggle Targets";
    private static final int MAX_INPUT_CANDIDATES = 500;

    private final MontoyaApi api;
    private final JPanel panel;
    private final TargetTableModel tableModel;
    private final JTable table;
    private final JSpinner minScoreSpinner;
    private final JSpinner topNSpinner;
    private final JCheckBox groupByHostBox;
    private final JCheckBox includeOutOfScopeBox;
    private final JLabel statusLabel;

    private ChunkContentScan smuggleProbeScan;
    private ImplicitZeroScan implicitZeroScan;
    private ParserDiscrepancyScan parserDiscrepancyScan;

    public SmuggleTargetTab(MontoyaApi api) {
        this.api = api;
        this.tableModel = new TargetTableModel();
        this.table = new TargetTable(tableModel);
        this.panel = new JPanel(new BorderLayout());
        this.minScoreSpinner = new JSpinner(new SpinnerNumberModel(50, -200, 200, 5));
        this.topNSpinner = new JSpinner(new SpinnerNumberModel(3, 1, 50, 1));
        this.groupByHostBox = new JCheckBox("Group by host", true);
        this.includeOutOfScopeBox = new JCheckBox("Include out of scope", false);
        this.statusLabel = new JLabel(" ");
        buildUi();
    }

    /** The Swing component to hand to {@code userInterface().registerSuiteTab(...)}. */
    public JComponent component() {
        return panel;
    }

    private void buildUi() {
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        toolbar.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        toolbar.add(new JButton(new AbstractAction("Refresh from Proxy History") {
            @Override
            public void actionPerformed(ActionEvent e) {
                refreshFromProxyHistory();
            }
        }));
        toolbar.add(new JButton(new AbstractAction("Refresh from Site Map") {
            @Override
            public void actionPerformed(ActionEvent e) {
                refreshFromSiteMap();
            }
        }));
        toolbar.addSeparator();
        toolbar.add(new JLabel("Min score "));
        toolbar.add(minScoreSpinner);
        toolbar.addSeparator();
        toolbar.add(new JLabel("Top N per host "));
        toolbar.add(topNSpinner);
        toolbar.addSeparator();
        toolbar.add(groupByHostBox);
        toolbar.addSeparator();
        toolbar.add(includeOutOfScopeBox);

        ChangeListener reapplyFilters = e -> tableModel.applyFilters(
                (Integer) minScoreSpinner.getValue(),
                (Integer) topNSpinner.getValue(),
                groupByHostBox.isSelected());
        minScoreSpinner.addChangeListener(reapplyFilters);
        topNSpinner.addChangeListener(reapplyFilters);
        groupByHostBox.addActionListener(e -> tableModel.applyFilters(
                (Integer) minScoreSpinner.getValue(),
                (Integer) topNSpinner.getValue(),
                groupByHostBox.isSelected()));

        table.setRowHeight(28);
        table.setAutoCreateRowSorter(true);
        TableRowSorter<TargetTableModel> sorter = new TableRowSorter<>(tableModel);
        sorter.toggleSortOrder(TargetTableModel.COL_SCORE);
        sorter.toggleSortOrder(TargetTableModel.COL_SCORE); // descending
        table.setRowSorter(sorter);

        TableColumnModel cols = table.getColumnModel();
        cols.getColumn(TargetTableModel.COL_SCORE).setPreferredWidth(60);
        cols.getColumn(TargetTableModel.COL_METHOD).setPreferredWidth(70);
        cols.getColumn(TargetTableModel.COL_HOST).setPreferredWidth(200);
        cols.getColumn(TargetTableModel.COL_PATH).setPreferredWidth(280);
        cols.getColumn(TargetTableModel.COL_STATUS).setPreferredWidth(60);
        cols.getColumn(TargetTableModel.COL_REASONING).setPreferredWidth(260);
        cols.getColumn(TargetTableModel.COL_ACTION_STATUS).setPreferredWidth(180);
        cols.getColumn(TargetTableModel.COL_ACTIONS).setPreferredWidth(680);

        ActionsCell actionsCell = new ActionsCell(this::dispatchAction);
        cols.getColumn(TargetTableModel.COL_ACTIONS).setCellRenderer(actionsCell);
        cols.getColumn(TargetTableModel.COL_ACTIONS).setCellEditor(actionsCell);

        JPanel statusBar = new JPanel(new BorderLayout());
        statusBar.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        statusBar.add(statusLabel, BorderLayout.WEST);

        panel.add(toolbar, BorderLayout.NORTH);
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        panel.add(statusBar, BorderLayout.SOUTH);
    }

    private void refreshFromProxyHistory() {
        runRefresh("Proxy History", () -> {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            List<HttpRequestResponse> out = new ArrayList<>(Math.min(history.size(), MAX_INPUT_CANDIDATES));
            for (int i = history.size() - 1; i >= 0 && out.size() < MAX_INPUT_CANDIDATES; i--) {
                ProxyHttpRequestResponse phrr = history.get(i);
                if (phrr == null || phrr.finalRequest() == null) {
                    continue;
                }
                HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(phrr.finalRequest(), phrr.originalResponse());
                if (shouldIncludeByScope(rr)) {
                    out.add(rr);
                }
            }
            Collections.reverse(out);
            return out;
        });
    }

    private void refreshFromSiteMap() {
        runRefresh("Site Map", () -> {
            List<HttpRequestResponse> items = api.siteMap().requestResponses();
            List<HttpRequestResponse> scoped = new ArrayList<>(Math.min(items.size(), MAX_INPUT_CANDIDATES));
            for (int i = items.size() - 1; i >= 0 && scoped.size() < MAX_INPUT_CANDIDATES; i--) {
                HttpRequestResponse rr = items.get(i);
                if (shouldIncludeByScope(rr)) {
                    scoped.add(rr);
                }
            }
            // Site map can be enormous; cap at the most recently observed in-scope entries.
            Collections.reverse(scoped);
            return scoped;
        });
    }

    private void runRefresh(String label, Supplier<List<HttpRequestResponse>> source) {
        setStatus("Scoring " + label + "...");
        new SwingWorker<List<SmuggleCandidate>, Void>() {
            @Override
            protected List<SmuggleCandidate> doInBackground() {
                List<HttpRequestResponse> raw = source.get();
                List<SmuggleCandidate> scored = new ArrayList<>(raw.size());
                for (HttpRequestResponse rr : raw) {
                    SmuggleCandidate cand = scoreOne(rr);
                    if (cand != null) {
                        scored.add(cand);
                    }
                }
                return scored;
            }

            @Override
            protected void done() {
                try {
                    List<SmuggleCandidate> scored = get();
                    tableModel.setAllCandidates(scored,
                            (Integer) minScoreSpinner.getValue(),
                            (Integer) topNSpinner.getValue(),
                            groupByHostBox.isSelected());
                    setStatus("Scored " + scored.size() + " requests from " + label
                            + "; showing " + tableModel.getRowCount() + " after filtering");
                } catch (Exception ex) {
                    setStatus("Refresh failed: " + ex.getMessage());
                    JOptionPane.showMessageDialog(panel, "Failed to refresh: " + ex,
                            "Smuggle Targets", JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private boolean shouldIncludeByScope(HttpRequestResponse rr) {
        if (includeOutOfScopeBox.isSelected()) {
            return true;
        }
        try {
            HttpRequest request = rr == null ? null : rr.request();
            return request != null && request.isInScope();
        } catch (Throwable ignored) {
            try {
                HttpRequest request = rr == null ? null : rr.request();
                return request != null && request.url() != null && api.scope().isInScope(request.url());
            } catch (Throwable ignoredAgain) {
                return false;
            }
        }
    }

    private SmuggleCandidate scoreOne(HttpRequestResponse rr) {
        try {
            HttpRequest req = rr.request();
            if (req == null) {
                return null;
            }
            HttpService service = req.httpService();
            String host = service != null ? service.host() : "";
            String method = req.method() == null ? "" : req.method();
            String fullPath = req.path() == null ? "" : req.path();
            int q = fullPath.indexOf('?');
            String pathOnly = q >= 0 ? fullPath.substring(0, q) : fullPath;
            String query = q >= 0 ? fullPath.substring(q + 1) : "";

            Map<String, String> reqHeaders = headersToLowerCaseMap(toHeaderPairs(req));
            int contentLength = parseIntSafe(reqHeaders.get("content-length"), 0);

            boolean isHttp2 = false;
            try {
                byte[] reqBytes = req.toByteArray() != null ? req.toByteArray().getBytes() : new byte[0];
                isHttp2 = Utilities.isHTTP2(reqBytes);
            } catch (Throwable t) {
                // Best-effort signal; the scorer treats this as one bonus among many.
            }

            SmuggleTargetScorer.ParsedRequest preq = new SmuggleTargetScorer.ParsedRequest(
                    method, host, pathOnly, query, reqHeaders, contentLength, isHttp2);

            HttpResponse resp = rr.response();
            int status = 0;
            Map<String, String> respHeaders = Collections.emptyMap();
            if (resp != null) {
                try {
                    status = resp.statusCode();
                } catch (Exception ignored) {
                    status = 0;
                }
                respHeaders = headersToLowerCaseMap(toHeaderPairs(resp));
            }

            SmuggleTargetScorer.ParsedResponse presp = new SmuggleTargetScorer.ParsedResponse(status, respHeaders);
            SmuggleTargetScorer.ScoreResult score = SmuggleTargetScorer.score(preq, presp);
            return new SmuggleCandidate(rr, score, method, host, fullPath, status);
        } catch (Throwable t) {
            // One bad row must not poison the whole refresh.
            return null;
        }
    }

    private static List<String[]> toHeaderPairs(HttpRequest req) {
        List<String[]> out = new ArrayList<>();
        if (req == null || req.headers() == null) {
            return out;
        }
        req.headers().forEach(h -> out.add(new String[]{h.name(), h.value()}));
        return out;
    }

    private static List<String[]> toHeaderPairs(HttpResponse resp) {
        List<String[]> out = new ArrayList<>();
        if (resp == null || resp.headers() == null) {
            return out;
        }
        resp.headers().forEach(h -> out.add(new String[]{h.name(), h.value()}));
        return out;
    }

    private static Map<String, String> headersToLowerCaseMap(List<String[]> pairs) {
        Map<String, String> out = new HashMap<>(pairs.size() * 2);
        for (String[] p : pairs) {
            if (p == null || p.length < 2 || p[0] == null) {
                continue;
            }
            // Keep the first occurrence; that matches what the scorer treats as the "primary" header.
            String key = p[0].toLowerCase(Locale.ROOT);
            out.putIfAbsent(key, p[1] == null ? "" : p[1]);
        }
        return out;
    }

    private static int parseIntSafe(String s, int fallback) {
        if (s == null) {
            return fallback;
        }
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private void setStatus(String text) {
        SwingUtilities.invokeLater(() -> statusLabel.setText(text == null ? " " : text));
    }

    private synchronized ChunkContentScan smuggleProbeScan() {
        if (smuggleProbeScan == null) {
            smuggleProbeScan = new ChunkContentScan("Smuggle probe (target picker)");
        }
        return smuggleProbeScan;
    }

    private synchronized ParserDiscrepancyScan parserDiscrepancyScan() {
        if (parserDiscrepancyScan == null) {
            // Leave insideScanner=false so findings are reported through the
            // scan's normal organizer/site-map pipeline. The DAST wrapper sets
            // insideScanner=true because it adapts findings into an AuditResult
            // returned to Burp Pro's scanner; the target-picker has no such
            // adapter and would otherwise silently drop discoveries.
            parserDiscrepancyScan = new ParserDiscrepancyScan("Parser discrepancy scan (target picker)");
        }
        return parserDiscrepancyScan;
    }

    void dispatchAction(String action, SmuggleCandidate cand) {
        if (cand == null || cand.requestResponse == null) {
            return;
        }
        HttpRequestResponse rr = cand.requestResponse;
        switch (action) {
            case "repeater":
                api.repeater().sendToRepeater(rr.request());
                setStatus("Sent " + summarize(cand) + " to Repeater.");
                break;
            case "organizer":
                api.organizer().sendToOrganizer(rr);
                setStatus("Sent " + summarize(cand) + " to Organizer.");
                break;
            case "smuggle":
                launchSmuggleProbe(rr, cand);
                break;
            case "cl0":
                launchImplicitZeroProbe(rr, cand);
                break;
            case "smart":
                launchSmartScan(rr, cand);
                break;
            case "parser":
                launchParserDiscrepancy(rr, cand);
                break;
            case "diagnose":
                launchDesyncAgent(rr, cand);
                break;
            default:
                break;
        }
    }

    private void launchSmuggleProbe(HttpRequestResponse rr, SmuggleCandidate cand) {
        String startMessage = "Launching Smuggle probe on " + summarize(cand) + " (running in background)...";
        setActionStatus(cand, "Smuggle probe running...");
        setStatus(startMessage);
        Utilities.out("Smuggle Target Picker: " + startMessage);
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                try {
                    HttpService montoyaService = rr.request().httpService();
                    IHttpService legacyService = Utilities.helpers.buildHttpService(
                            montoyaService.host(), montoyaService.port(), montoyaService.secure());
                    byte[] bytes = rr.request().toByteArray().getBytes();
                    String unreachable = targetUnreachableReason(legacyService, bytes);
                    if (unreachable != null) {
                        return "Smuggle probe not run for " + summarize(cand) + ": " + unreachable;
                    }
                    smuggleProbeScan().doScan(bytes, legacyService);
                    return "Smuggle probe finished for " + summarize(cand)
                            + ". This only covers the classic CL.TE/TE.CL probe; try CL.0 or Parser discrepancy for broader coverage.";
                } catch (Throwable t) {
                    String detail = t.getMessage() == null ? t.toString() : t.getMessage();
                    Utilities.err("Smuggle Target Picker: Smuggle probe failed for " + summarize(cand)
                            + ": " + detail);
                    return "Smuggle probe failed for " + summarize(cand) + ": " + detail;
                }
            }

            @Override
            protected void done() {
                try {
                    String message = get();
                    setActionStatus(cand, summarizeLaunchStatus(message, "Smuggle probe"));
                    setStatus(message);
                    Utilities.out("Smuggle Target Picker: " + message);
                } catch (Exception ex) {
                    setActionStatus(cand, "Smuggle probe failed");
                    String message = "Smuggle probe failed: " + ex.getMessage();
                    setStatus(message);
                    Utilities.err("Smuggle Target Picker: " + message);
                }
            }
        }.execute();
    }

    private synchronized ImplicitZeroScan implicitZeroScan() {
        if (implicitZeroScan == null) {
            implicitZeroScan = new ImplicitZeroScan("CL.0 (target picker)");
        }
        return implicitZeroScan;
    }

    private void launchImplicitZeroProbe(HttpRequestResponse rr, SmuggleCandidate cand) {
        String startMessage = "Launching CL.0 probe on " + summarize(cand) + " (running in background)...";
        setActionStatus(cand, "CL.0 probe running...");
        setStatus(startMessage);
        Utilities.out("Smuggle Target Picker: " + startMessage);
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                try {
                    HttpService montoyaService = rr.request().httpService();
                    IHttpService legacyService = Utilities.helpers.buildHttpService(
                            montoyaService.host(), montoyaService.port(), montoyaService.secure());
                    byte[] bytes = rr.request().toByteArray().getBytes();
                    String unreachable = targetUnreachableReason(legacyService, bytes);
                    if (unreachable != null) {
                        return "CL.0 probe not run for " + summarize(cand) + ": " + unreachable;
                    }
                    implicitZeroScan().doScan(bytes, legacyService);
                    return "CL.0 probe finished for " + summarize(cand)
                            + ". If a tentative CL.0 issue was confirmed, it should appear in Organizer/site map.";
                } catch (Throwable t) {
                    String detail = t.getMessage() == null ? t.toString() : t.getMessage();
                    Utilities.err("Smuggle Target Picker: CL.0 probe failed for " + summarize(cand)
                            + ": " + detail);
                    return "CL.0 probe failed for " + summarize(cand) + ": " + detail;
                }
            }

            @Override
            protected void done() {
                try {
                    String message = get();
                    setActionStatus(cand, summarizeLaunchStatus(message, "CL.0 probe"));
                    setStatus(message);
                    Utilities.out("Smuggle Target Picker: " + message);
                } catch (Exception ex) {
                    setActionStatus(cand, "CL.0 probe failed");
                    String message = "CL.0 probe failed: " + ex.getMessage();
                    setStatus(message);
                    Utilities.err("Smuggle Target Picker: " + message);
                }
            }
        }.execute();
    }

    private void launchSmartScan(HttpRequestResponse rr, SmuggleCandidate cand) {
        String startMessage = "Launching Smart scan on " + summarize(cand)
                + " (running the extension's applicable checks in background)...";
        setActionStatus(cand, "Smart scan starting...");
        setStatus(startMessage);
        Utilities.out("Smuggle Target Picker: " + startMessage);
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                int attempted = 0;
                int skipped = 0;
                int failed = 0;
                List<Scan> scans = smartScanChecks();
                if (scans.isEmpty()) {
                    return "Smart scan could not find registered checks. Try reloading the extension.";
                }

                try {
                    HttpService montoyaService = rr.request().httpService();
                    IHttpService legacyService = Utilities.helpers.buildHttpService(
                            montoyaService.host(), montoyaService.port(), montoyaService.secure());
                    byte[] requestBytes = rr.request().toByteArray().getBytes();
                    byte[] responseBytes = rr.response() == null ? null : rr.response().toByteArray().getBytes();
                    String unreachable = targetUnreachableReason(legacyService, requestBytes);
                    if (unreachable != null) {
                        return "Smart scan not run for " + summarize(cand) + ": " + unreachable;
                    }

                    for (Scan scan : scans) {
                        if (scan == null) {
                            continue;
                        }
                        String scanName = scan.name == null ? scan.getClass().getSimpleName() : scan.name;
                        IHttpRequestResponse legacyMessage = legacyMessage(requestBytes, responseBytes, legacyService);
                        try {
                            if (!scan.shouldScan(legacyMessage)) {
                                skipped++;
                                continue;
                            }
                            attempted++;
                            setActionStatus(cand, "Smart scan: " + scanName);
                            Utilities.out("Smuggle Target Picker: Smart scan running " + scanName
                                    + " on " + summarize(cand));
                            scan.doScan(legacyMessage);
                        } catch (Throwable t) {
                            failed++;
                            String detail = t.getMessage() == null ? t.toString() : t.getMessage();
                            Utilities.err("Smuggle Target Picker: Smart scan check failed: "
                                    + scanName + " on " + summarize(cand) + ": " + detail);
                        }
                    }
                } catch (Throwable t) {
                    String detail = t.getMessage() == null ? t.toString() : t.getMessage();
                    Utilities.err("Smuggle Target Picker: Smart scan failed for " + summarize(cand)
                            + ": " + detail);
                    return "Smart scan failed for " + summarize(cand) + ": " + detail;
                }

                return "Smart scan finished for " + summarize(cand) + ": ran "
                        + attempted + " checks, skipped " + skipped + ", failed " + failed
                        + ". Any findings should appear in Organizer/site map and the extension output pane.";
            }

            @Override
            protected void done() {
                try {
                    String message = get();
                    setActionStatus(cand, summarizeLaunchStatus(message, "Smart scan"));
                    setStatus(message);
                    Utilities.out("Smuggle Target Picker: " + message);
                } catch (Exception ex) {
                    setActionStatus(cand, "Smart scan failed");
                    String message = "Smart scan failed: " + ex.getMessage();
                    setStatus(message);
                    Utilities.err("Smuggle Target Picker: " + message);
                }
            }
        }.execute();
    }

    private List<Scan> smartScanChecks() {
        List<Scan> checks = new ArrayList<>();
        if (BulkScan.scans != null) {
            for (Scan scan : BulkScan.scans) {
                if (scan == null || scan.name == null) {
                    continue;
                }
                String name = scan.name;
                if ("Launch all scans".equals(name) || name.contains("(target picker)")) {
                    continue;
                }
                checks.add(scan);
            }
        }
        if (!checks.isEmpty()) {
            return checks;
        }

        // Fallback for unusual load orders where the legacy scan registry has not
        // been populated yet. Keep this aligned with BurpExtender's registered scans.
        checks.add(new ParserDiscrepancyScan("Parser discrepancy scan (target picker smart fallback)"));
        checks.add(new HeaderRemovalScan("Header removal (target picker smart fallback)"));
        checks.add(new ImplicitZeroScan("CL.0 (target picker smart fallback)"));
        checks.add(new ClientDesyncScan("Client-side desync (target picker smart fallback)"));
        checks.add(new PauseDesyncScan("Pause-based desync (target picker smart fallback)"));
        checks.add(new ConnectionStateScan("Connection-state (target picker smart fallback)"));
        checks.add(new ChunkSizeScan("Chunk size scan (target picker smart fallback)"));
        checks.add(new ChunkContentScan("Smuggle probe (target picker smart fallback)"));
        checks.add(new HTTP2Scan("HTTP/2 probe (target picker smart fallback)"));
        checks.add(new HeadScanTE("HTTP/2 Tunnel probe TE (target picker smart fallback)"));
        checks.add(new H2TunnelScan("HTTP/2 Tunnel probe CL (target picker smart fallback)"));
        checks.add(new HiddenHTTP2("HTTP/2-hidden probe (target picker smart fallback)"));
        checks.add(new HTTP2Scheme("HTTP/2 :scheme probe (target picker smart fallback)"));
        checks.add(new HTTP2DualPath("HTTP/2 dual :path probe (target picker smart fallback)"));
        checks.add(new HTTP2Method("HTTP/2 :method probe (target picker smart fallback)"));
        checks.add(new HTTP2FakePseudo("HTTP/2 fake-pseudo probe (target picker smart fallback)"));
        return checks;
    }

    private static String targetUnreachableReason(IHttpService service, byte[] requestBytes) {
        if (service == null) {
            return "no HTTP service was available for this request";
        }
        if (requestBytes == null || requestBytes.length == 0) {
            return "the selected request has no request bytes";
        }
        try {
            Resp baseline = Scan.request(service, requestBytes, 0, false);
            if (baseline == null) {
                return "baseline request returned no result";
            }
            if (baseline.failed() || baseline.timedOut() || baseline.getStatus() == 0) {
                return "baseline request failed or timed out (status " + baseline.getStatus() + ")";
            }
            if (baseline.getResponse() == null || baseline.getResponse().length == 0) {
                return "baseline request received no response bytes";
            }
            return null;
        } catch (Throwable t) {
            String detail = t.getMessage() == null ? t.toString() : t.getMessage();
            return "baseline request errored: " + detail;
        }
    }

    private static String summarizeLaunchStatus(String message, String actionName) {
        if (message == null) {
            return actionName + " finished";
        }
        if (message.contains("not run")) {
            return "Target unreachable";
        }
        if (message.startsWith(actionName + " failed") || message.contains(" failed")) {
            return actionName + " failed";
        }
        return actionName + " finished";
    }

    private static IHttpRequestResponse legacyMessage(byte[] requestBytes, byte[] responseBytes, IHttpService service) {
        return new IHttpRequestResponse() {
            private byte[] request = requestBytes == null ? null : requestBytes.clone();
            private byte[] response = responseBytes == null ? null : responseBytes.clone();
            private String comment = "";
            private String highlight = "";
            private IHttpService httpService = service;

            @Override
            public byte[] getRequest() {
                return request;
            }

            @Override
            public void setRequest(byte[] message) {
                request = message;
            }

            @Override
            public byte[] getResponse() {
                return response;
            }

            @Override
            public void setResponse(byte[] message) {
                response = message;
            }

            @Override
            public String getComment() {
                return comment;
            }

            @Override
            public void setComment(String comment) {
                this.comment = comment;
            }

            @Override
            public String getHighlight() {
                return highlight;
            }

            @Override
            public void setHighlight(String color) {
                highlight = color;
            }

            @Override
            public IHttpService getHttpService() {
                return httpService;
            }

            @Override
            public void setHttpService(IHttpService httpService) {
                this.httpService = httpService;
            }
        };
    }

    private void launchParserDiscrepancy(HttpRequestResponse rr, SmuggleCandidate cand) {
        String startMessage = "Launching Parser discrepancy on " + summarize(cand) + " (running in background)...";
        setActionStatus(cand, "Parser discrepancy running...");
        setStatus(startMessage);
        Utilities.out("Smuggle Target Picker: " + startMessage);
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                try {
                    HttpService montoyaService = rr.request().httpService();
                    IHttpService legacyService = Utilities.helpers.buildHttpService(
                            montoyaService.host(), montoyaService.port(), montoyaService.secure());
                    byte[] bytes = rr.request().toByteArray().getBytes();
                    String unreachable = targetUnreachableReason(legacyService, bytes);
                    if (unreachable != null) {
                        return "Parser discrepancy not run for " + summarize(cand) + ": " + unreachable;
                    }
                    Report report = parserDiscrepancyScan().doScan(rr.request());
                    if (report == null) {
                        return "Parser discrepancy finished for " + summarize(cand) + ": no findings.";
                    }
                    return "Parser discrepancy found an issue on " + summarize(cand) + ".";
                } catch (Throwable t) {
                    String detail = t.getMessage() == null ? t.toString() : t.getMessage();
                    Utilities.err("Smuggle Target Picker: Parser discrepancy failed for " + summarize(cand)
                            + ": " + detail);
                    return "Parser discrepancy failed for " + summarize(cand) + ": " + detail;
                }
            }

            @Override
            protected void done() {
                try {
                    String message = get();
                    setActionStatus(cand, message.contains("found an issue")
                            ? "Parser discrepancy found issue"
                            : summarizeLaunchStatus(message, "Parser discrepancy"));
                    setStatus(message);
                    Utilities.out("Smuggle Target Picker: " + message);
                } catch (Exception ex) {
                    setActionStatus(cand, "Parser discrepancy failed");
                    String message = "Parser discrepancy failed: " + ex.getMessage();
                    setStatus(message);
                    Utilities.err("Smuggle Target Picker: " + message);
                }
            }
        }.execute();
    }

    private void launchDesyncAgent(HttpRequestResponse rr, SmuggleCandidate cand) {
        try {
            HttpService service = rr.request().httpService();
            byte[] reqBytes = rr.request().toByteArray().getBytes();
            byte[] respBytes = rr.response() == null ? null : rr.response().toByteArray().getBytes();
            DesyncAgentDialog.open(api, reqBytes, respBytes, service, null, null);
            setActionStatus(cand, "Desync agent opened");
            setStatus("Opened desync agent for " + summarize(cand)
                    + " (builds a single-connection CL.0 PoC; uses Burp AI if enabled).");
            Utilities.out("Smuggle Target Picker: opened desync agent for " + summarize(cand));
        } catch (Throwable t) {
            String detail = t.getMessage() == null ? t.toString() : t.getMessage();
            setActionStatus(cand, "Desync agent failed");
            setStatus("Desync agent failed for " + summarize(cand) + ": " + detail);
            Utilities.err("Smuggle Target Picker: desync agent failed for " + summarize(cand) + ": " + detail);
        }
    }

    private void setActionStatus(SmuggleCandidate cand, String actionStatus) {
        cand.actionStatus = actionStatus == null ? "" : actionStatus;
        SwingUtilities.invokeLater(() -> tableModel.fireRowChanged(cand));
    }

    private static String summarize(SmuggleCandidate cand) {
        return cand.method + " " + cand.host + cand.path;
    }

    // ---------- table model ----------

    static final class TargetTableModel extends AbstractTableModel {
        static final int COL_SCORE = 0;
        static final int COL_METHOD = 1;
        static final int COL_HOST = 2;
        static final int COL_PATH = 3;
        static final int COL_STATUS = 4;
        static final int COL_REASONING = 5;
        static final int COL_ACTION_STATUS = 6;
        static final int COL_ACTIONS = 7;
        private static final String[] COLUMNS = {
                "Score", "Method", "Host", "Path", "Status", "Reasoning", "Last Action", "Actions"
        };

        private final List<SmuggleCandidate> all = new ArrayList<>();
        private final List<SmuggleCandidate> visible = new ArrayList<>();

        @Override
        public int getRowCount() {
            return visible.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMNS[column];
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == COL_SCORE || columnIndex == COL_STATUS) {
                return Integer.class;
            }
            return Object.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == COL_ACTIONS;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            SmuggleCandidate cand = visible.get(rowIndex);
            switch (columnIndex) {
                case COL_SCORE:
                    return cand.score.score;
                case COL_METHOD:
                    return cand.method;
                case COL_HOST:
                    return cand.host;
                case COL_PATH:
                    return cand.path;
                case COL_STATUS:
                    return cand.status;
                case COL_REASONING:
                    return summarizeReasons(cand.score.reasons);
                case COL_ACTION_STATUS:
                    return cand.actionStatus;
                case COL_ACTIONS:
                    return cand;
                default:
                    return null;
            }
        }

        SmuggleCandidate candidateAt(int modelRow) {
            return visible.get(modelRow);
        }

        void fireRowChanged(SmuggleCandidate cand) {
            int idx = visible.indexOf(cand);
            if (idx >= 0) {
                fireTableRowsUpdated(idx, idx);
            }
        }

        void setAllCandidates(List<SmuggleCandidate> scored, int minScore, int topN, boolean groupByHost) {
            all.clear();
            all.addAll(scored);
            applyFilters(minScore, topN, groupByHost);
        }

        void applyFilters(int minScore, int topN, boolean groupByHost) {
            Map<String, SmuggleCandidate> bestByKey = new LinkedHashMap<>();
            for (SmuggleCandidate cand : all) {
                if (cand.score.score < minScore) {
                    continue;
                }
                String key = cand.score.dedupKey;
                SmuggleCandidate existing = bestByKey.get(key);
                if (existing == null || existing.score.score < cand.score.score) {
                    bestByKey.put(key, cand);
                }
            }
            List<SmuggleCandidate> deduped = new ArrayList<>(bestByKey.values());
            deduped.sort((a, b) -> Integer.compare(b.score.score, a.score.score));

            List<SmuggleCandidate> next;
            if (groupByHost) {
                Map<String, Integer> perHostCount = new HashMap<>();
                next = new ArrayList<>(deduped.size());
                for (SmuggleCandidate c : deduped) {
                    String host = c.host == null ? "" : c.host.toLowerCase(Locale.ROOT);
                    int n = perHostCount.getOrDefault(host, 0);
                    if (n < topN) {
                        next.add(c);
                        perHostCount.put(host, n + 1);
                    }
                }
            } else {
                next = deduped;
            }
            SwingUtilities.invokeLater(() -> {
                visible.clear();
                visible.addAll(next);
                fireTableDataChanged();
            });
        }

        private static String summarizeReasons(List<SmuggleTargetScorer.Reason> reasons) {
            if (reasons == null || reasons.isEmpty()) {
                return "(no signals)";
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < reasons.size(); i++) {
                if (i > 0) {
                    sb.append(", ");
                }
                SmuggleTargetScorer.Reason r = reasons.get(i);
                sb.append(r.label).append(' ').append(r.delta >= 0 ? "+" : "").append(r.delta);
            }
            return sb.toString();
        }
    }

    // ---------- table with tooltips ----------

    private static final class TargetTable extends JTable {
        private final TargetTableModel model;

        TargetTable(TargetTableModel model) {
            super(model);
            this.model = model;
        }

        @Override
        public String getToolTipText(MouseEvent event) {
            int viewRow = rowAtPoint(event.getPoint());
            int viewCol = columnAtPoint(event.getPoint());
            if (viewRow < 0 || viewCol < 0) {
                return null;
            }
            int modelRow = convertRowIndexToModel(viewRow);
            int modelCol = convertColumnIndexToModel(viewCol);
            if (modelRow < 0 || modelCol < 0) {
                return null;
            }
            SmuggleCandidate cand = model.candidateAt(modelRow);
            if (modelCol == TargetTableModel.COL_REASONING) {
                StringBuilder sb = new StringBuilder("<html><b>Reasoning</b><br>");
                for (SmuggleTargetScorer.Reason r : cand.score.reasons) {
                    sb.append(escapeHtml(r.toString())).append("<br>");
                }
                sb.append("</html>");
                return sb.toString();
            }
            if (modelCol == TargetTableModel.COL_PATH) {
                return cand.path;
            }
            return super.getToolTipText(event);
        }

        private static String escapeHtml(String s) {
            if (s == null) {
                return "";
            }
            StringBuilder out = new StringBuilder(s.length());
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '<':
                        out.append("&lt;");
                        break;
                    case '>':
                        out.append("&gt;");
                        break;
                    case '&':
                        out.append("&amp;");
                        break;
                    default:
                        out.append(c);
                }
            }
            return out.toString();
        }
    }

    // ---------- per-row action buttons ----------

    /** Functional interface so the renderer/editor never holds a reference to the enclosing tab. */
    interface ActionDispatcher {
        void dispatch(String action, SmuggleCandidate cand);
    }

    /**
     * Dual-purpose JTable cell that doubles as renderer and editor. The same
     * physical panel is reused for both roles so button clicks always reach a
     * live action listener regardless of whether the row is currently being
     * "edited" (i.e. focused).
     */
    private static final class ActionsCell extends AbstractCellEditor
            implements TableCellRenderer, TableCellEditor {

        private final JPanel rendererPanel;
        private final JPanel editorPanel;
        private SmuggleCandidate editorRow;

        ActionsCell(ActionDispatcher dispatcher) {
            this.rendererPanel = buildPanel(null);
            this.editorPanel = buildPanel(action -> {
                ActionDispatcher d = dispatcher;
                SmuggleCandidate row = editorRow;
                fireEditingStopped();
                if (d != null && row != null) {
                    d.dispatch(action, row);
                }
            });
        }

        private static JPanel buildPanel(java.util.function.Consumer<String> onClick) {
            JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
            p.setOpaque(true);
            p.setBackground(Color.WHITE);
            addButton(p, "Repeater", onClick == null ? null : e -> onClick.accept("repeater"));
            addButton(p, "Organizer", onClick == null ? null : e -> onClick.accept("organizer"));
            addButton(p, "Smart scan", onClick == null ? null : e -> onClick.accept("smart"));
            addButton(p, "Smuggle probe", onClick == null ? null : e -> onClick.accept("smuggle"));
            addButton(p, "CL.0 probe", onClick == null ? null : e -> onClick.accept("cl0"));
            addButton(p, "Parser discrepancy", onClick == null ? null : e -> onClick.accept("parser"));
            addButton(p, "Diagnose desync", onClick == null ? null : e -> onClick.accept("diagnose"));
            return p;
        }

        private static void addButton(JPanel parent, String label, java.awt.event.ActionListener l) {
            JButton b = new JButton(label);
            b.setMargin(new java.awt.Insets(1, 6, 1, 6));
            b.setFocusable(false);
            if (l != null) {
                b.addActionListener(l);
            }
            parent.add(b);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                        boolean hasFocus, int row, int column) {
            rendererPanel.setBackground(isSelected ? table.getSelectionBackground() : table.getBackground());
            return rendererPanel;
        }

        @Override
        public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected,
                                                      int row, int column) {
            editorRow = (value instanceof SmuggleCandidate) ? (SmuggleCandidate) value : null;
            editorPanel.setBackground(table.getSelectionBackground());
            return editorPanel;
        }

        @Override
        public Object getCellEditorValue() {
            return editorRow;
        }
    }
}
