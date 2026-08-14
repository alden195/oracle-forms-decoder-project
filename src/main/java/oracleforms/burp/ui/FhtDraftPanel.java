package oracleforms.burp.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;
import oracleforms.codec.FhtEdit;
import oracleforms.codec.FhtParser;
import oracleforms.codec.FhtWriter;
import oracleforms.codec.PropertyValues;
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

    private byte[] plaintext = new byte[0];

    FhtDraftPanel() {
        header.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        header.setVerticalAlignment(SwingConstants.TOP);

        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(table.getRowHeight() + 4);
        table.setDefaultRenderer(Object.class, new EditedCellRenderer());
        widths(30, 220, 90, 320);

        rendered.setEditable(false);
        rendered.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), new JScrollPane(rendered));
        split.setResizeWeight(0.6);

        panel.add(header, BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);
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
        header.setText(headerHtml);
        rendered.setText(renderedText);
        rendered.setCaretPosition(0);

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

    /** Whether the user has changed anything. */
    boolean isModified() {
        return model.rows.stream().anyMatch(Row::isEdited);
    }

    /** Discards pending edits, returning every cell to the value that was decoded. */
    void revert() {
        for (Row row : model.rows) {
            row.value = row.property.value();
        }
        model.fireTableDataChanged();
    }

    /**
     * The draft's bytes with the user's edits spliced in.
     *
     * <p>Never throws. Burp calls this whenever it wants the message, including at moments where an
     * exception would surface as a broken tab, so a failure returns the unedited bytes and reports
     * itself through {@code problem}.
     */
    byte[] editedPlaintext(List<String> problem) {
        List<FhtEdit> edits = new ArrayList<>();
        for (Row row : model.rows) {
            if (row.isEdited()) {
                edits.add(new FhtEdit(row.property, row.value));
            }
        }
        if (edits.isEmpty()) {
            return plaintext.clone();
        }
        try {
            return FhtWriter.applyEdits(plaintext, edits);
        } catch (Exception e) {
            problem.add(e.getMessage());
            return plaintext.clone();
        }
    }

    /** How many edits are pending, for the header line. */
    int editCount() {
        return (int) model.rows.stream().filter(Row::isEdited).count();
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
    }
}
