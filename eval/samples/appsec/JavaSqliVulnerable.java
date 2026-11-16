import java.sql.*;

public class UserDao {
    public ResultSet find(Connection conn, String name) throws SQLException {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
