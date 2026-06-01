package burp;

import javax.swing.JMenuItem;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class SuggestAttack implements IContextMenuFactory {

    static final String UNKNOWN = "";
    static final String CLTE = "CL.TE";
    static final String TECL = "TE.CL";
    static final String H2TE = "H2.TE";
    static final String H2TUNNEL = "H2-TUNNEL";

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> options = new ArrayList<>();

        IHttpRequestResponse message = selectedMessage(invocation);
        if (message == null || message.getRequest() == null) {
            return options;
        }

        byte[] requestBytes = message.getRequest();
        // Use ISO-8859-1 so raw HTTP bytes >= 0x80 (used by spaceFF/nbsp/shy/nel/unispace
        // smuggling payloads) survive the byte->String round-trip on UTF-8 JVMs.
        String headers = Utils.getHeaders(new String(requestBytes, StandardCharsets.ISO_8859_1)).toLowerCase();
        boolean http2 = Utilities.isHTTP2(requestBytes);

        if (headers.contains("chunked") || headers.contains("transfer-encoding")) {
            if (http2) {
                options.add(buildAttackMenuItem(message, H2TE));
                return options;
            }

            String type = detectTypeFromSelectedIssue(invocation);
            if (type.equals(UNKNOWN)) {
                options.add(buildAttackMenuItem(message, CLTE));
                options.add(buildAttackMenuItem(message, TECL));
            } else {
                options.add(buildAttackMenuItem(message, type));
            }
            return options;
        }

        if (http2 && Utilities.containsBytes(requestBytes, "FOO BAR AAH".getBytes())) {
            options.add(buildAttackMenuItem(message, H2TUNNEL));
        }

        return options;
    }

    private static IHttpRequestResponse selectedMessage(IContextMenuInvocation invocation) {
        if (invocation == null) {
            return null;
        }
        IHttpRequestResponse[] selected = invocation.getSelectedMessages();
        if (selected == null || selected.length == 0) {
            return null;
        }
        return selected[0];
    }

    private static String detectTypeFromSelectedIssue(IContextMenuInvocation invocation) {
        if (invocation.getSelectedIssues() == null || invocation.getSelectedIssues().length == 0) {
            return UNKNOWN;
        }
        String name = invocation.getSelectedIssues()[0].getIssueName();
        if (name == null) {
            return UNKNOWN;
        }
        if (name.contains(CLTE)) {
            return CLTE;
        }
        if (name.contains(TECL)) {
            return TECL;
        }
        if (name.contains(H2TE)) {
            return H2TE;
        }
        return UNKNOWN;
    }

    private static JMenuItem buildAttackMenuItem(IHttpRequestResponse message, String type) {
        JMenuItem item = new JMenuItem("Smuggle attack (" + type + ")");
        item.addActionListener(new LaunchSuggestedAttack(message, type));
        return item;
    }
}

class LaunchSuggestedAttack implements ActionListener {

    private final IHttpRequestResponse message;
    private final String type;

    LaunchSuggestedAttack(IHttpRequestResponse message, String type) {
        this.message = message;
        this.type = type;
    }

    @Override
    public void actionPerformed(ActionEvent e) {

        String PAYLOAD = "\r\n1\r\nZ\r\nQ\r\n\r\n";
        String H2PAYLOAD = "\r\na\r\n\r\n0\r\n\r\n";
        // Decode with ISO-8859-1 to preserve raw HTTP bytes verbatim through this
        // pipeline; Burp's helpers.stringToBytes uses the same encoding on the way out.
        String request = new String(message.getRequest(), StandardCharsets.ISO_8859_1);
        String script;

        if (type.equals(SuggestAttack.H2TE)) {
            request = request.replaceFirst(H2PAYLOAD, "\r\n0\r\n\r\n");
            script = Utilities.getResource("/H2-TE.py");
        } else if (type.equals(SuggestAttack.H2TUNNEL)) {
            if (!request.contains("\r\n0\r\n\r\nFOO BAR")) {
                // stop Turbo from autofixing the content-length
                request = request.replaceFirst("Content-Length", "Content-length");
            }
            script = Utilities.getResource("/H2-TUNNEL.py");
        }
        else if (type.equals(SuggestAttack.CLTE)) {
            request = request.replaceFirst(PAYLOAD, "\r\n0\r\n\r\n");
            script = Utilities.getResource("/CL-TE.py");
        } else if (type.equals(SuggestAttack.TECL)) {
            script = Utilities.getResource("/TE-CL.py");
        } else {

            if (request.contains(PAYLOAD)) {
                // this is CL.TE
                script = Utilities.getResource("/CL-TE.py");
                request = request.replaceFirst(PAYLOAD, "\r\n0\r\n\r\n");
            } else {
                // this is either a normal chunked request, or TE.CL
                script = Utilities.getResource("/TE-CL.py");
            }
        }

        // amend the script to try and ensure the smuggled request gets a different response
        byte[] resp = message.getResponse();
        if (resp != null ) {
            String path = Utilities.helpers.analyzeRequest(message).getUrl().getPath();
            short responseCode = Utilities.helpers.analyzeResponse(resp).getStatusCode();
            if (responseCode == 404) {
                String newPath = "/";
                if (path.equals(newPath)) {
                    newPath = "/robots.txt";
                }

                script = script.replace("/hopefully404", newPath);
            }
        }

        new TurboIntruderFrame(message, new int[]{}, script, Utilities.helpers.stringToBytes(request), null).actionPerformed(e);
    }

}
