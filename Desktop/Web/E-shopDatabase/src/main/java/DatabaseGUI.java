import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class DatabaseGUI extends JFrame {
    private DatabaseManager dbManager;

    private JComboBox<String> operationComboBox;
    private JTextField tableNameField, conditionField, columnsField, valuesField;
    private JButton executeButton;

    public DatabaseGUI(DatabaseManager dbManager) {
        this.dbManager = dbManager;

        setTitle("Database GUI");
        setSize(400, 300);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new GridLayout(6, 2));

        JLabel operationLabel = new JLabel("Operation:");
        String[] operations = {"Insert data", "Delete data", "Update data"};
        operationComboBox = new JComboBox<>(operations);
        add(operationLabel);
        add(operationComboBox);

        JLabel tableNameLabel = new JLabel("Table Name:");
        tableNameField = new JTextField();
        add(tableNameLabel);
        add(tableNameField);

        JLabel conditionLabel = new JLabel("Condition:");
        conditionField = new JTextField();
        add(conditionLabel);
        add(conditionField);

        JLabel columnsLabel = new JLabel("Columns (for update):");
        columnsField = new JTextField();
        add(columnsLabel);
        add(columnsField);

        JLabel valuesLabel = new JLabel("Values (comma-separated):");
        valuesField = new JTextField();
        add(valuesLabel);
        add(valuesField);

        executeButton = new JButton("Execute");
        executeButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String operation = (String) operationComboBox.getSelectedItem();
                String tableName = tableNameField.getText();
                String condition = conditionField.getText();
                String columns = columnsField.getText();
                String values = valuesField.getText();

                switch (operation) {
                    case "Insert data":
                        dbManager.insertData(tableName, values.split(","));
                        break;
                    case "Delete data":
                        dbManager.deleteData(tableName, condition);
                        break;
                    case "Update data":
                        dbManager.updateData(tableName, columns.split(","), values.split(","), condition);
                        break;
                    default:
                        JOptionPane.showMessageDialog(null, "Invalid operation selected");
                }
            }
        });
        add(executeButton);

        setVisible(true);
    }

    public static void main(String[] args) {
        DatabaseManager dbManager = new DatabaseManager();
        SwingUtilities.invokeLater(() -> new DatabaseGUI(dbManager));
    }
}
