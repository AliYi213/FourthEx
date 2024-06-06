import java.sql.*;

public class DatabaseManager {
    private Connection connection;
    public DatabaseManager() {
        connect();
    }
    private void connect() {
        try {
            connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/ali", "ali", "123");
            System.out.println("Connected to the database.");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    public void disconnect() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
                System.out.println("Disconnected from the database.");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    public void insertData(String tableName, String[] values) {
        try {
            Statement statement = connection.createStatement();
            String query = "INSERT INTO " + tableName + " VALUES (" + String.join(", ", values) + ")";
            statement.executeUpdate(query);
            System.out.println("Data inserted successfully.");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    public void deleteData(String tableName, String condition) {
        try {
            Statement statement = connection.createStatement();
            String query = "DELETE FROM " + tableName + " WHERE " + condition;
            statement.executeUpdate(query);
            System.out.println("Data deleted successfully.");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    public void updateData(String tableName, String[] columns, String[] values, String condition) {
        try {
            Statement statement = connection.createStatement();
            StringBuilder query = new StringBuilder("UPDATE " + tableName + " SET ");
            for (int i = 0; i < columns.length; i++) {
                query.append(columns[i]).append("=").append(values[i]);
                if (i < columns.length - 1) {
                    query.append(", ");
                }
            }
            query.append(" WHERE ").append(condition);
            statement.executeUpdate(query.toString());
            System.out.println("Data updated successfully.");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
