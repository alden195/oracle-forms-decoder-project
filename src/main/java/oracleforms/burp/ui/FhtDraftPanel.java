package oracleforms.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.editor.RawEditor;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Component;
import java.awt.Font;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JToggleButton;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;
import oracleforms.codec.FhtEdit;
import oracleforms.codec.FhtParser;
import oracleforms.codec.FhtWriter;
import oracleforms.codec.PropertyValues;
import oracleforms.codec.TextIndexEdits;
import oracleforms.codec.StringDictionary;
import oracleforms.codec.model.FhtMessage;
import oracleforms.codec.model.FhtPacket;
import oracleforms.codec.model.FhtProperty;
import oracleforms.codec.model.PropertyValue;

/**
 * The editing surface for a plaintext FHT draft.
 *
 * <p>A property table over the decoded message, with the value column editable for properties the
 * writer can reproduce. Everything else is shown but locked, with the reason in its own column —
 * "extended type: the payload is not decoded, only measured" tells a user far more than a greyed-out
 * cell does.
 *
 * <p>Editability is decided by {@link FhtWriter#editRefusal}, which re-encodes each property with its
 * own unchanged value and compares against the original bytes. So a cell is offered only when the
 * encoder has already demonstrated, on these exact bytes, that it can reproduce them.
 */
final class FhtDraftPanel {

    private static final String[] COLUMNS = {"#", "Property", "Type", "Value", "Editable"};

    private static final String TABLE_CARD = "table";
    private static final String RAW_CARD = "raw";

    /** Which surface currently owns the buffer. Never both (architecture &sect;6.10 C). */
    private enum Surface { TABLE, RAW }

    /** One property, plus whatever the user has typed over it. */
    private static final class Row {
        final int messageIndex;
        final FhtProperty property;
        final String refusal;
        PropertyValue value;

        Row(int messageIndex, FhtProperty property, String refusal) {
            this.messageIndex = messageIndex;
            this.property = property;
            this.refusal = refusal;
            this.value = property.value();
        }

        boolean isEdited() {
            return !value.equals(property.value());
        }

        boolean isEditable() {
            return refusal == null;
        }
    }

    private final JPanel panel = new JPanel(new BorderLayout());
    private final JLabel header = new JLabel();
    private final JTextArea rendered = new JTextArea();
    private final Model model = new Model();
    private final JTable table = new JTable(model);

    private final RawEditor raw;
    private final JPanel surfaces = new JPanel(new CardLayout());
    private final JToggleButton structuredButton = new JToggleButton("Structured", true);
    private final JToggleButton rawButton = new JToggleButton("Raw");
    private final JLabel surfaceStatus = new JLabel(" ");

    /** The committed buffer. Pending changes live in whichever surface is live, never here. */
    private byte[] plaintext = new byte[0];

    /** What was loaded, so "has the user changed anything" survives a surface switch. */
    private byte[] original = new byte[0];

    private Surface surface = Surface.TABLE;
    private boolean editable;

    /** Guards the toggle listeners against re-entering while a switch is being applied. */
    private boolean switching;

    FhtDraftPanel(MontoyaApi api) {
        this.raw = api.userInterface().createRawEditor();

        header.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        header.setVerticalAlignment(SwingConstants.TOP);

        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(table.getRowHeight() + 4);
        table.setDefaultRenderer(Object.class, new EditedCellRenderer());
        widths(30, 220, 90, 320);

        // 6d.1, half of it. Swing's default is to leave a cell editor open when focus moves away,
        // so setValueAt never fires and the model still holds the old value. In the Intercept tab
        // that is not an edge case: Forward is a different button in a different panel, so focus
        // loss without pressing Enter is what always happens. The other half is the explicit
        // stopEditing() on every read, because the invariant belongs where the question is asked.
        table.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);

        rendered.setEditable(false);
        rendered.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), new JScrollPane(rendered));
        split.setResizeWeight(0.6);

        surfaces.add(split, TABLE_CARD);
        surfaces.add(raw.uiComponent(), RAW_CARD);

        panel.add(header, BorderLayout.NORTH);
        panel.add(surfaces, BorderLayout.CENTER);
        panel.add(buildSurfaceBar(), BorderLayout.SOUTH);
    }

    /**
     * The surface toggle, and the line that says what the parser makes of the current bytes.
     *
     * <p>Two live editors over one buffer is the classic way to lose a user's work, so exactly one
     * of them owns it at a time and switching commits (architecture &sect;6.10 C).
     */
    private JPanel buildSurfaceBar() {
        ButtonGroup group = new ButtonGroup();
        group.add(structuredButton);
        group.add(rawButton);

        structuredButton.setToolTipText("Typed property values. Every edit is checked against the "
                + "encoder before it is offered, so nothing here can corrupt the message.");
        rawButton.setToolTipText("The decoded bytes, unrestricted: extended payloads, unknown type "
                + "markers, the message header, and length changes of any size. Warns if the "
                + "result no longer parses, but does not stop you.");

        structuredButton.addActionListener(e -> switchTo(Surface.TABLE));
        rawButton.addActionListener(e -> switchTo(Surface.RAW));

        JPanel bar = new JPanel(new BorderLayout());
        JPanel buttons = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 4, 2));
        buttons.add(new JLabel("Edit as: "));
        buttons.add(structuredButton);
        buttons.add(rawButton);

        surfaceStatus.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
        bar.add(buttons, BorderLayout.WEST);
        bar.add(surfaceStatus, BorderLayout.CENTER);
        return bar;
    }

    private void widths(int... widths) {
        for (int i = 0; i < widths.length && i < table.getColumnCount(); i++) {
            TableColumn column = table.getColumnModel().getColumn(i);
            column.setPreferredWidth(widths[i]);
        }
    }

    Component uiComponent() {
        return panel;
    }

    /**
     * Loads a draft's plaintext, replacing anything shown before.
     *
     * <p>Discards pending edits, which is correct: they were offsets into the previous message's
     * bytes and mean nothing against these.
     */
    void show(byte[] draftPlaintext, String headerHtml, String renderedText, boolean editable) {
        this.plaintext = draftPlaintext.clone();
        this.original = draftPlaintext.clone();
        this.editable = editable;
        header.setText(headerHtml);
        rendered.setText(renderedText);
        rendered.setCaretPosition(0);

        // A surface left on Raw from the previous message would present the new one as bytes with
        // no explanation of why the table vanished.
        this.surface = Surface.TABLE;
        switching = true;
        structuredButton.setSelected(true);
        switching = false;
        ((CardLayout) surfaces.getLayout()).show(surfaces, TABLE_CARD);

        raw.setEditable(editable);
        raw.setContents(ByteArray.byteArray(plaintext));
        rawButton.setEnabled(editable);
        describeBuffer(plaintext);

        rebuildRows();
    }

    /** Re-parses the committed buffer and rebuilds the property rows against it. */
    private void rebuildRows() {
        FhtPacket packet = new FhtParser().parse(plaintext, new StringDictionary());
        List<Row> rows = new ArrayList<>();
        for (int i = 0; i < packet.messages().size(); i++) {
            FhtMessage message = packet.messages().get(i);
            for (FhtProperty property : message.properties()) {
                String refusal = editable
                        ? FhtWriter.editRefusal(plaintext, property).orElse(null)
                        : "this view is read-only";
                if (refusal == null && !PropertyValues.isTextEditable(property.value())) {
                    refusal = "no text form for this value";
                }
                rows.add(new Row(i + 1, property, refusal));
            }
        }
        model.replace(rows);
    }

    /**
     * Moves the buffer to the other surface, committing whatever the live one holds on the way.
     *
     * <p>Table to Raw splices the pending cell edits and loads the result; Raw to Table adopts the
     * bytes and re-parses them. Either way there is never pending state in the hidden view, which is
     * the only reliable defence against losing a user's work across a switch.
     */
    private void switchTo(Surface target) {
        if (switching || target == surface) {
            return;
        }
        switching = true;
        try {
            List<String> problem = new ArrayList<>(1);
            List<String> notes = new ArrayList<>(2);
            byte[] committed = editedPlaintext(problem, notes);

            if (!problem.isEmpty() && target == Surface.RAW) {
                // The splice failed, so the table's pending edits cannot be represented as bytes.
                // Staying put is the honest answer: switching would silently discard them.
                surfaceStatus.setText("Cannot switch: " + problem.get(0));
                structuredButton.setSelected(true);
                return;
            }

            plaintext = committed;
            surface = target;

            if (target == Surface.RAW) {
                raw.setContents(ByteArray.byteArray(plaintext));
                ((CardLayout) surfaces.getLayout()).show(surfaces, RAW_CARD);
            } else {
                rebuildRows();
                ((CardLayout) surfaces.getLayout()).show(surfaces, TABLE_CARD);
            }
            describeBuffer(plaintext);
            if (!notes.isEmpty()) {
                // The bytes about to appear in the raw view contain a change the user did not type.
                // Seeing it there without being told is exactly the surprise this whole path avoids.
                surfaceStatus.setText("<html>" + escapeHtml(String.join(", ", notes))
                        + " &mdash; adjusted to stay inside the text you edited, and now part of "
                        + "these bytes.</html>");
            }
        } finally {
            switching = false;
        }
    }

    /**
     * Says what the parser makes of the current bytes, without preventing anything.
     *
     * <p>Deliberately the opposite of the identity gate in {@code FhtWriter}, and the difference is
     * who is asserting. The writer refuses a splice when <em>it</em> cannot prove a change is
     * faithful — that is the codec doubting itself, and it should fail closed. The raw surface sends
     * what the <em>user</em> wrote, having said plainly what it thinks of it: sending bytes this
     * parser calls malformed is the entire point of a manipulation tool, and this parser's opinion is
     * a hypothesis about someone else's protocol (architecture &sect;6.10 C).
     */
    private void describeBuffer(byte[] bytes) {
        FhtPacket packet = new FhtParser().parse(bytes, new StringDictionary());
        if (packet.outcome().isComplete()) {
            surfaceStatus.setText(bytes.length + " bytes, " + packet.messages().size()
                    + " message(s), parses cleanly.");
        } else {
            surfaceStatus.setText("<html><b>Warning:</b> " + bytes.length + " bytes; "
                    + escapeHtml(packet.outcome().describe())
                    + ". It will still be sent exactly as written.</html>");
        }
    }

    /**
     * Says what else will move when this draft is sent, at the moment the user types it.
     *
     * <p>On the EDT, where the cell was committed. Waiting until the message is read would tell the
     * user after they had pressed Forward, which is no use to them at all.
     */
    private void announceCompanionEdits() {
        List<FhtEdit> edits = new ArrayList<>();
        for (Row row : model.rows) {
            if (row.isEdited()) {
                edits.add(new FhtEdit(row.property, row.value));
            }
        }
        List<TextIndexEdits.Adjustment> adjustments = companionEdits(edits);
        if (adjustments.isEmpty()) {
            describeBuffer(plaintext);
            return;
        }
        StringBuilder text = new StringBuilder("<html>Also sending: ");
        for (int i = 0; i < adjustments.size(); i++) {
            text.append(i == 0 ? "" : ", ")
                    .append(escapeHtml(adjustments.get(i).description()));
        }
        surfaceStatus.setText(text.append(
                " &mdash; these index into the text you changed and pointed past its end.</html>")
                .toString());
    }

    private static String escapeHtml(String text) {
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /**
     * Commits any cell the user is still typing into.
     *
     * <p>The other half of 6d.1, and the half that has to be right. The client property above
     * handles the ordinary focus-loss case, but it is a Swing implementation detail; the invariant
     * is "the model is current whenever anybody asks it a question", and that belongs where the
     * question is answered rather than only where focus happens to move.
     */
    private void stopEditing() {
        if (table.isEditing() && table.getCellEditor() != null) {
            table.getCellEditor().stopCellEditing();
        }
    }

    /** Whether the user has changed anything, on either surface. */
    boolean isModified() {
        stopEditing();
        if (surface == Surface.RAW) {
            return !Arrays.equals(original, currentRawBytes());
        }
        return !Arrays.equals(original, plaintext) || model.rows.stream().anyMatch(Row::isEdited);
    }

    /** Discards pending edits, returning every cell to the value that was decoded. */
    void revert() {
        stopEditing();
        for (Row row : model.rows) {
            row.value = row.property.value();
        }
        model.fireTableDataChanged();
    }

    private byte[] currentRawBytes() {
        try {
            return raw.getContents().getBytes();
        } catch (RuntimeException e) {
            return plaintext.clone();
        }
    }

    /**
     * The draft's bytes with the user's edits spliced in.
     *
     * <p>Never throws. Burp calls this whenever it wants the message, including at moments where an
     * exception would surface as a broken tab, so a failure returns the unedited bytes and reports
     * itself through {@code problem}.
     */
    byte[] editedPlaintext(List<String> problem) {
        return editedPlaintext(problem, new ArrayList<>());
    }

    /**
     * The draft's bytes with the user's edits spliced in, and whatever had to move with them.
     *
     * @param problem receives the reason a splice failed, if one did
     * @param notes   receives one line per companion adjustment, so the caller can say what else
     *                changed. Nothing is ever adjusted silently
     */
    byte[] editedPlaintext(List<String> problem, List<String> notes) {
        // Before anything reads the model. Without this a value typed into a cell and then abandoned
        // by clicking Forward is still sitting in the cell editor, setValueAt has never fired, and
        // the message goes out unedited -- which is indistinguishable from the feature not working.
        stopEditing();

        if (surface == Surface.RAW) {
            // The raw surface is authoritative when it is live, and it is unrestricted by design:
            // the user is writing bytes, and nothing here is entitled to add any of its own.
            return currentRawBytes();
        }

        List<FhtEdit> edits = new ArrayList<>();
        for (Row row : model.rows) {
            if (row.isEdited()) {
                edits.add(new FhtEdit(row.property, row.value));
            }
        }
        if (edits.isEmpty()) {
            return plaintext.clone();
        }
        for (TextIndexEdits.Adjustment adjustment : companionEdits(edits)) {
            edits.add(adjustment.edit());
            notes.add(adjustment.description());
        }
        try {
            return FhtWriter.applyEdits(plaintext, edits);
        } catch (Exception e) {
            problem.add(e.getMessage());
            return plaintext.clone();
        }
    }

    /**
     * The changes that have to travel with the user's, because they index into what was edited.
     *
     * <p>A text item's caret and selection are offsets into its own value (see
     * {@link TextIndexEdits}), so changing the text's length can leave them pointing past its end —
     * a message no client could send, and one the Forms runtime is free to ignore. The buffer is
     * re-parsed rather than reusing the rows' properties because both describe the same bytes, and
     * offsets are what the splice works from.
     */
    private List<TextIndexEdits.Adjustment> companionEdits(List<FhtEdit> edits) {
        try {
            return TextIndexEdits.forEdits(
                    new FhtParser().parse(plaintext, new StringDictionary()), edits);
        } catch (RuntimeException e) {
            // A consistency nicety must never be the thing that stops an edit going out.
            return List.of();
        }
    }

    /** How many edits are pending, for the header line. */
    int editCount() {
        stopEditing();
        if (surface == Surface.RAW) {
            return Arrays.equals(original, currentRawBytes()) ? 0 : 1;
        }
        int spliced = Arrays.equals(original, plaintext) ? 0 : 1;
        return spliced + (int) model.rows.stream().filter(Row::isEdited).count();
    }

    private final class Model extends AbstractTableModel {

        private List<Row> rows = new ArrayList<>();

        void replace(List<Row> replacement) {
            this.rows = replacement;
            fireTableDataChanged();
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
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 3 && rows.get(rowIndex).isEditable();
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Row row = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> row.messageIndex;
                case 1 -> row.property.name() + (row.property.isSensitive() ? "  [sensitive]" : "");
                case 2 -> row.value.getClass().getSimpleName().replace("Value", "");
                case 3 -> PropertyValues.editableText(row.value);
                default -> row.refusal == null ? "yes" : row.refusal;
            };
        }

        /**
         * Accepts a typed value only if it reads back as the same shape.
         *
         * <p>A rejected edit leaves the cell as it was. Refusing at type-time rather than at
         * send-time is the difference between "that is not a number" and a blocked send six edits
         * later with no indication which one caused it.
         */
        @Override
        public void setValueAt(Object value, int rowIndex, int columnIndex) {
            if (columnIndex != 3) {
                return;
            }
            Row row = rows.get(rowIndex);
            Optional<PropertyValue> parsed =
                    PropertyValues.parseLike(row.property.value(), String.valueOf(value));
            if (parsed.isPresent()) {
                row.value = parsed.get();
                fireTableRowsUpdated(rowIndex, rowIndex);
                announceCompanionEdits();
            } else {
                // Repaint so the cell snaps back to the value that is actually held.
                fireTableRowsUpdated(rowIndex, rowIndex);
            }
        }
    }

    /** Marks edited rows in bold so a modified draft is obvious at a glance. */
    private final class EditedCellRenderer extends javax.swing.table.DefaultTableCellRenderer {

        @Override
        public Component getTableCellRendererComponent(
                JTable table, Object value, boolean isSelected, boolean hasFocus,
                int row, int column) {

            Component component = super.getTableCellRendererComponent(
                    table, value, isSelected, hasFocus, row, column);
            Row model = FhtDraftPanel.this.model.rows.get(row);
            component.setFont(component.getFont().deriveFont(
                    model.isEdited() ? Font.BOLD : Font.PLAIN));
            if (!model.isEditable() && !isSelected) {
                component.setEnabled(false);
            } else {
                component.setEnabled(true);
            }
            return component;
        }
    }

    /** Exposed so the request editor can leave the table alone when a message is not a draft. */
    void showMessage(String text) {
        header.setText(text);
        rendered.setText("");
        model.replace(new ArrayList<>());
        plaintext = new byte[0];
        original = new byte[0];
        surfaceStatus.setText(" ");
    }
}
