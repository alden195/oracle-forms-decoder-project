package oracleforms.burp.ui;

import burp.api.montoya.MontoyaApi;
import java.awt.BorderLayout;
import java.awt.Frame;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import oracleforms.burp.DecodeService;
import oracleforms.burp.history.PragmaHistorySource;
import oracleforms.burp.history.RetroactiveKeyScanner;
import oracleforms.session.Handshake;
import oracleforms.session.KeyDerivation;
import oracleforms.session.KeySource;
import oracleforms.session.KeyStoreJson;
import oracleforms.session.SessionKey;
import oracleforms.session.SessionKeyStore;
import oracleforms.session.Direction;
import oracleforms.session.PragmaBody;
import oracleforms.session.StreamReplayer;
import oracleforms.session.ValidationFixtures;

/**
 * The key store UI: what is known, and how to add, remove or move it.
 *
 * <p>Two rules shape this class. Dialogs are parented to the Burp suite frame so they position
 * correctly and come forward with Burp (BApp criterion 10). And anything touching proxy history or
 * the store runs on a background thread, with the table updated back on the EDT (criterion 5) —
 * a retroactive scan over a large project is exactly the operation that would otherwise freeze the
 * whole UI.
 */
public final class SessionsTab extends JPanel {

    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final MontoyaApi api;
    private final SessionKeyStore keyStore;
    private final DecodeService decodeService;
    private final KeyDerivation derivation;

    private final SessionTableModel tableModel = new SessionTableModel();
    private final JTable table = new JTable(tableModel);
    private final JTextArea log = new JTextArea(8, 80);
    private final ExecutorService worker;

    public SessionsTab(
            MontoyaApi api,
            SessionKeyStore keyStore,
            DecodeService decodeService,
            KeyDerivation derivation) {
        super(new BorderLayout());
        this.api = api;
        this.keyStore = keyStore;
        this.decodeService = decodeService;
        this.derivation = derivation;
        this.worker = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "oracle-forms-sessions");
            t.setDaemon(true);
            return t;
        });

        table.setAutoCreateRowSorter(true);
        log.setEditable(false);
        log.setLineWrap(true);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), new JScrollPane(log));
        split.setResizeWeight(0.7);

        add(buildToolbar(), BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
        add(buildFooter(), BorderLayout.SOUTH);

        refresh();
    }

    private JPanel buildToolbar() {
        JPanel bar = new JPanel();
        bar.setLayout(new BoxLayout(bar, BoxLayout.X_AXIS));
        bar.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        bar.add(button("Refresh", this::refresh));
        bar.add(Box.createHorizontalStrut(6));
        bar.add(button("Scan history for keys", this::scanHistory));
        bar.add(Box.createHorizontalStrut(6));
        bar.add(button("Add key manually…", this::addManualKey));
        bar.add(Box.createHorizontalStrut(6));
        bar.add(button("Forget selected", this::forgetSelected));
        bar.add(Box.createHorizontalStrut(6));
        bar.add(button("Clear all keys…", this::clearAll));
        bar.add(Box.createHorizontalStrut(18));
        bar.add(button("Export…", this::export));
        bar.add(Box.createHorizontalStrut(6));
        bar.add(button("Import…", this::importKeys));
        bar.add(Box.createHorizontalStrut(6));
        bar.add(button("Export validation fixtures…", this::exportFixtures));
        bar.add(Box.createHorizontalGlue());
        return bar;
    }

    private JPanel buildFooter() {
        JPanel footer = new JPanel(new BorderLayout());
        footer.setBorder(BorderFactory.createEmptyBorder(0, 8, 6, 8));
        footer.add(new JLabel(
                "<html><i>Session keys are stored in the Burp project file, which is not "
                        + "encrypted. Use \"Clear all keys\" before sharing a project.</i></html>"),
                BorderLayout.WEST);
        return footer;
    }

    private JButton button(String text, Runnable action) {
        JButton button = new JButton(text);
        button.addActionListener(e -> action.run());
        return button;
    }

    /**
     * Submits background work, tolerating an already-unloaded extension.
     *
     * <p>The tab's panel survives in Burp's UI until the suite tab is removed, so a click can still
     * arrive after {@link #shutdown()} has stopped the worker. Left unguarded that throws
     * {@link RejectedExecutionException} straight onto the EDT.
     */
    private void submit(Runnable work) {
        try {
            worker.submit(work);
        } catch (RejectedExecutionException e) {
            appendLog("The extension has been unloaded; reload it to use the Sessions tab.");
        }
    }

    // Actions. Each one hands the slow part to the worker thread and comes back to the EDT to
    // touch Swing.

    private void refresh() {
        submit(() -> {
            try {
                List<SessionKey> keys = keyStore.list();
                SwingUtilities.invokeLater(() -> tableModel.setRows(keys));
            } catch (RuntimeException e) {
                reportError("Could not read the key store", e);
            }
        });
    }

    private void scanHistory() {
        appendLog("Scanning proxy history for Pragma 1 handshakes…");
        submit(() -> {
            try {
                RetroactiveKeyScanner.ScanResult result =
                        new RetroactiveKeyScanner(api, keyStore, derivation).scan(false);

                StringBuilder summary = new StringBuilder();
                summary.append("Scan complete: ")
                        .append(result.sessionsSeen()).append(" session(s) with a handshake, ")
                        .append(result.keysRecovered()).append(" key(s) recovered, ")
                        .append(result.alreadyKnown()).append(" already known, ")
                        .append(result.incomplete()).append(" incomplete.");
                if (result.symmetryFailures() > 0) {
                    summary.append("\n!! ").append(result.symmetryFailures())
                            .append(" session(s) failed the Pragma 3 structural check — the "
                                    + "shared-key assumption may not hold for them.");
                }
                appendLog(summary + "\n" + result.report());
                refresh();
            } catch (RuntimeException e) {
                reportError("History scan failed", e);
            }
        });
    }

    private void addManualKey() {
        JTextField sessionField = new JTextField(40);
        JTextField keyField = new JTextField(20);
        JTextField labelField = new JTextField(20);

        JPanel form = new JPanel();
        form.setLayout(new BoxLayout(form, BoxLayout.Y_AXIS));
        form.add(new JLabel("JSESSIONID (not JSESSIONID_FORMS):"));
        form.add(sessionField);
        form.add(Box.createVerticalStrut(8));
        form.add(new JLabel("Key, 5 bytes of hex (e.g. 33cdae22bc):"));
        form.add(keyField);
        form.add(Box.createVerticalStrut(8));
        form.add(new JLabel("Label (optional):"));
        form.add(labelField);

        int choice = JOptionPane.showConfirmDialog(suiteFrame(), form,
                "Add an Oracle Forms session key", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE);
        if (choice != JOptionPane.OK_OPTION) {
            return;
        }

        String sessionId = sessionField.getText().trim();
        try {
            byte[] key = SessionKey.parseKeyHex(keyField.getText());
            long now = System.currentTimeMillis();
            SessionKey sessionKey = new SessionKey(
                    sessionId, key, "", now, now, labelField.getText().trim(), KeySource.MANUAL);

            submit(() -> {
                keyStore.put(sessionKey);
                decodeService.invalidateSession(sessionId);
                appendLog("Stored a manual key for session " + sessionId + ".");
                refresh();
            });
        } catch (IllegalArgumentException e) {
            JOptionPane.showMessageDialog(suiteFrame(), e.getMessage(),
                    "That key could not be used", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void forgetSelected() {
        List<String> selected = selectedSessionIds();
        if (selected.isEmpty()) {
            return;
        }
        submit(() -> {
            for (String sessionId : selected) {
                keyStore.forget(sessionId);
                decodeService.invalidateSession(sessionId);
            }
            appendLog("Forgot " + selected.size() + " session key(s).");
            refresh();
        });
    }

    private void clearAll() {
        int choice = JOptionPane.showConfirmDialog(suiteFrame(),
                "Delete every stored session key from this project?\nThis cannot be undone.",
                "Clear all keys", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (choice != JOptionPane.YES_OPTION) {
            return;
        }
        submit(() -> {
            keyStore.clear();
            appendLog("Cleared all stored keys.");
            refresh();
        });
    }

    private void export() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File("oracle-forms-keys.json"));
        if (chooser.showSaveDialog(suiteFrame()) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        java.io.File file = chooser.getSelectedFile();
        submit(() -> {
            try {
                List<SessionKey> keys = keyStore.list();
                Files.writeString(file.toPath(), KeyStoreJson.export(keys), StandardCharsets.UTF_8);
                appendLog("Exported " + keys.size() + " key(s) to " + file);
            } catch (IOException | RuntimeException e) {
                reportError("Export failed", e);
            }
        });
    }

    /**
     * Dumps the few bytes per session that key-derivation validation needs, byte for byte.
     *
     * <p>This is the route out of the project's longest-standing gap: every protocol assumption so
     * far has been tested against synthetic sessions, because the MCP server's escaped-text rendering
     * of message bodies is lossy for binary and cannot yield the handshake randoms. Here the bytes
     * have never left the JVM, so they are exact.
     *
     * <p>Runs off the EDT — it walks proxy history once per session.
     */
    private void exportFixtures() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File("oracle-forms-fixtures.json"));
        if (chooser.showSaveDialog(suiteFrame()) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        java.io.File file = chooser.getSelectedFile();
        submit(() -> {
            try {
                List<ValidationFixtures.Fixture> fixtures = new ArrayList<>();
                int incomplete = 0;

                for (SessionKey key : keyStore.list()) {
                    PragmaHistorySource history =
                            PragmaHistorySource.forSession(api, key.sessionId());

                    ValidationFixtures.Fixture fixture = new ValidationFixtures.Fixture(
                            key.sessionId(),
                            key.host(),
                            bodyAt(history, Direction.REQUEST, Handshake.HANDSHAKE_PRAGMA),
                            bodyAt(history, Direction.RESPONSE, Handshake.HANDSHAKE_PRAGMA),
                            bodyAt(history, Direction.REQUEST, StreamReplayer.FIRST_ENCRYPTED_PRAGMA),
                            bodyAt(history, Direction.RESPONSE, StreamReplayer.FIRST_ENCRYPTED_PRAGMA));

                    if (!fixture.isComplete()) {
                        incomplete++;
                    }
                    fixtures.add(fixture);
                }

                Files.writeString(file.toPath(), ValidationFixtures.export(fixtures),
                        StandardCharsets.UTF_8);
                appendLog("Exported " + fixtures.size() + " fixture(s) to " + file
                        + (incomplete > 0
                                ? " (" + incomplete + " missing a handshake or pragma 3, so they "
                                        + "cannot validate a key)"
                                : "")
                        + ". These contain the handshake randoms - treat them like the keys.");
            } catch (IOException | RuntimeException e) {
                reportError("Fixture export failed", e);
            }
        });
    }

    /** One captured body, trimmed to fixture size, or empty if it was never captured. */
    private static byte[] bodyAt(PragmaHistorySource history, Direction direction, int pragma) {
        return history.body(direction, pragma)
                .map(PragmaBody::body)
                .map(ValidationFixtures::trim)
                .orElseGet(() -> new byte[0]);
    }

    private void importKeys() {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(suiteFrame()) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        java.io.File file = chooser.getSelectedFile();
        submit(() -> {
            try {
                String json = Files.readString(file.toPath(), StandardCharsets.UTF_8);
                List<String> problems = new ArrayList<>();
                List<SessionKey> keys = KeyStoreJson.importFrom(json, problems);

                for (SessionKey key : keys) {
                    keyStore.put(key);
                    decodeService.invalidateSession(key.sessionId());
                }
                StringBuilder message = new StringBuilder(
                        "Imported " + keys.size() + " key(s) from " + file + ".");
                for (String problem : problems) {
                    message.append("\n  skipped: ").append(problem);
                }
                appendLog(message.toString());
                refresh();
            } catch (IOException | RuntimeException e) {
                reportError("Import failed", e);
            }
        });
    }

    private List<String> selectedSessionIds() {
        List<String> out = new ArrayList<>();
        for (int viewRow : table.getSelectedRows()) {
            out.add(tableModel.sessionIdAt(table.convertRowIndexToModel(viewRow)));
        }
        return out;
    }

    private Frame suiteFrame() {
        return api.userInterface().swingUtils().suiteFrame();
    }

    private void appendLog(String message) {
        SwingUtilities.invokeLater(() -> {
            log.append(message);
            log.append("\n");
            log.setCaretPosition(log.getDocument().getLength());
        });
    }

    private void reportError(String what, Throwable cause) {
        api.logging().logToError("Oracle Forms: " + what + ": " + cause);
        appendLog(what + ": " + cause);
    }

    /** Releases the tab's worker thread on unload (BApp criterion 6). */
    public void shutdown() {
        worker.shutdownNow();
        try {
            worker.awaitTermination(1, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static final class SessionTableModel extends AbstractTableModel {

        private static final String[] COLUMNS =
                {"JSESSIONID", "Key", "Host", "Source", "First seen", "Last seen", "Label"};

        private List<SessionKey> rows = List.of();

        void setRows(List<SessionKey> rows) {
            this.rows = rows;
            fireTableDataChanged();
        }

        String sessionIdAt(int row) {
            return rows.get(row).sessionId();
        }

        @Override
        public int getRowCount() {
            return rows.size();
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
        public Object getValueAt(int row, int column) {
            SessionKey key = rows.get(row);
            return switch (column) {
                case 0 -> key.sessionId();
                case 1 -> key.keyHex();
                case 2 -> key.host();
                case 3 -> key.source().wireName();
                case 4 -> formatTime(key.firstSeen());
                case 5 -> formatTime(key.lastSeen());
                default -> key.label();
            };
        }

        private static String formatTime(long epochMillis) {
            return epochMillis == 0 ? "" : TIMESTAMP.format(Instant.ofEpochMilli(epochMillis));
        }
    }
}
