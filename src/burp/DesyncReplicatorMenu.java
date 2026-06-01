package burp;

import burp.api.montoya.http.HttpService;

import javax.swing.JMenuItem;
import java.util.ArrayList;
import java.util.List;

/**
 * Right-click entry point for the desync "agent". Available on any selected
 * request (proxy history, site map, Repeater, and — most usefully — the request
 * attached to a smuggling issue in the Organizer / issue list), it opens
 * {@link DesyncAgentDialog} to build a single-connection CL.0 proof-of-concept and,
 * when Burp AI is enabled, explain how to replicate it manually.
 */
public class DesyncReplicatorMenu implements IContextMenuFactory {

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<>();
        IHttpRequestResponse message = selectedMessage(invocation);
        if (message == null || message.getRequest() == null) {
            return items;
        }

        final String issueText = selectedIssueText(invocation);
        final DesyncRepro.Type type = DesyncRepro.typeFromText(issueText);
        final String technique = parseTechnique(issueText);
        final String gadget = parseGadget(issueText);
        JMenuItem item = new JMenuItem("Diagnose / replicate desync (agent)");
        item.addActionListener(e -> launch(message, type, technique, gadget));
        items.add(item);
        return items;
    }

    private static void launch(IHttpRequestResponse message, DesyncRepro.Type type, String technique,
                               String gadget) {
        try {
            IHttpService legacy = message.getHttpService();
            HttpService service = HttpService.httpService(
                    legacy.getHost(), legacy.getPort(),
                    "https".equalsIgnoreCase(legacy.getProtocol()));
            DesyncAgentDialog.open(Utilities.montoyaApi, message.getRequest(),
                    message.getResponse(), service, type, technique, gadget);
        } catch (Throwable t) {
            Utilities.err("Desync agent: failed to launch: "
                    + (t.getMessage() == null ? t.toString() : t.getMessage()));
        }
    }

    private static IHttpRequestResponse selectedMessage(IContextMenuInvocation invocation) {
        if (invocation == null) {
            return null;
        }
        IHttpRequestResponse[] selected = invocation.getSelectedMessages();
        if (selected != null) {
            for (IHttpRequestResponse message : selected) {
                if (message != null && message.getRequest() != null) {
                    return message;
                }
            }
        }
        // Right-clicking a finding in the site map / issues view populates the
        // selected issues, not the selected messages, so recover the request from
        // the issue's attached HTTP messages.
        try {
            IScanIssue[] issues = invocation.getSelectedIssues();
            if (issues != null) {
                for (IScanIssue issue : issues) {
                    if (issue == null) {
                        continue;
                    }
                    IHttpRequestResponse[] messages = issue.getHttpMessages();
                    if (messages == null) {
                        continue;
                    }
                    for (IHttpRequestResponse message : messages) {
                        if (message != null && message.getRequest() != null) {
                            return message;
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
            // Best-effort.
        }
        return null;
    }

    /**
     * Concatenates the selected issues' names and details so we can sniff both the
     * desync class (CL.0/CL.TE/TE.CL) and, for CL.0, the Content-Length permutation.
     */
    private static String selectedIssueText(IContextMenuInvocation invocation) {
        try {
            if (invocation == null || invocation.getSelectedIssues() == null) {
                return null;
            }
            StringBuilder sb = new StringBuilder();
            for (IScanIssue issue : invocation.getSelectedIssues()) {
                if (issue == null) {
                    continue;
                }
                if (issue.getIssueName() != null) {
                    sb.append(issue.getIssueName()).append('\n');
                }
                if (issue.getIssueDetail() != null) {
                    sb.append(issue.getIssueDetail()).append('\n');
                }
            }
            return sb.length() == 0 ? null : sb.toString();
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String parseTechnique(String text) {
        if (text == null) {
            return null;
        }
        int marker = text.indexOf("CL.0 desync:");
        if (marker < 0) {
            marker = text.indexOf("0.CL:");
        }
        if (marker < 0) {
            return null;
        }
        int colon = text.indexOf(':', marker);
        if (colon < 0) {
            return null;
        }
        String rest = text.substring(colon + 1).trim();
        int pipe = rest.indexOf('|');
        if (pipe > 0) {
            rest = rest.substring(0, pipe);
        }
        rest = rest.trim();
        return rest.isEmpty() ? null : rest;
    }

    /**
     * The scanner titles a CL.0 finding {@code "CL.0 desync: <technique>|<gadget request line>"}.
     * The gadget (e.g. {@code GET /robots.txt HTTP/1.1} or {@code TRACE / HTTP/1.1}) is the exact
     * smuggled request line that worked, so we use it instead of a synthetic default. Only parsed
     * for the confirmed "CL.0 desync:" title; the "Potential 0.CL" title has no gadget.
     */
    private static String parseGadget(String text) {
        if (text == null) {
            return null;
        }
        int marker = text.indexOf("CL.0 desync:");
        if (marker < 0) {
            return null;
        }
        int colon = text.indexOf(':', marker);
        if (colon < 0) {
            return null;
        }
        String rest = text.substring(colon + 1);
        int pipe = rest.indexOf('|');
        if (pipe < 0) {
            return null;
        }
        String gadget = rest.substring(pipe + 1);
        int nl = gadget.indexOf('\n');
        if (nl >= 0) {
            gadget = gadget.substring(0, nl);
        }
        gadget = gadget.trim();
        // Only accept something that looks like a request line.
        if (gadget.isEmpty() || !gadget.contains(" HTTP/")) {
            return null;
        }
        return gadget;
    }
}
