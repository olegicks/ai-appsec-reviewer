import java.sql.*;

public class UserDao {
    public ResultSet find(Connection conn, String name) throws SQLException {
        PreparedStatement st = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        st.setString(1, name);
        return st.executeQuery();
    }
}
