package burp;

import javax.swing.JMenuItem;
import java.util.ArrayList;
import java.util.List;

public class SmuggleMenu implements IContextMenuFactory {

    SmuggleMenu() {
        Utilities.callbacks.registerContextMenuFactory(this);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> options = new ArrayList<>();
        IHttpRequestResponse[] reqs = invocation.getSelectedMessages();

        if (reqs == null || reqs.length != 1 || reqs[0] == null) {
            return options;
        }

        IHttpRequestResponse target = reqs[0];
        byte[] req = target.getRequest();
        if (req == null) {
            return options;
        }

        boolean hasBody = Utilities.getBodyStart(req) < req.length;
        boolean hasContentLength = Utilities.containsBytes(req, "Content-Length".getBytes());
        if (!hasBody && !hasContentLength) {
            return options;
        }

        options.add(buildMenuItem(
                "Convert body to chunked encoding",
                () -> target.setRequest(SmuggleScanBox.makeChunked(target.getRequest(), 0, 0))));

        options.add(buildMenuItem(
                "Gzip encode body",
                () -> target.setRequest(SmuggleScanBox.gzipBody(target.getRequest()))));

        return options;
    }

    private static JMenuItem buildMenuItem(String label, Runnable action) {
        JMenuItem item = new JMenuItem(label);
        item.addActionListener(e -> action.run());
        return item;
    }
}
