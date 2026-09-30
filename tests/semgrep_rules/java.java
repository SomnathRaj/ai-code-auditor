// Semgrep rule tests. Lines after a "rule id" annotation must match; lines after an "ok" annotation must not.
import java.security.MessageDigest;
import java.sql.*;
import javax.net.ssl.*;
import java.io.*;

public class Sample {
    void sqli(Connection conn, String id) throws Exception {
        Statement st = conn.createStatement();
        // ruleid: aca-java-sqli-string-built-query
        st.executeQuery("SELECT * FROM users WHERE id = " + id);
        String q = "DELETE FROM users WHERE id = " + id;
        // ruleid: aca-java-sqli-string-built-query
        st.executeUpdate(q);
        // ok: aca-java-sqli-string-built-query
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
    }

    void commands(String host) throws Exception {
        // ruleid: aca-java-command-injection
        Runtime.getRuntime().exec("ping -c 1 " + host);
        // ruleid: aca-java-command-injection
        new ProcessBuilder("sh", "-c", host).start();
        // ok: aca-java-command-injection
        new ProcessBuilder("ping", "-c", "1", host).start();
    }

    Object deser(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        // ruleid: aca-java-unsafe-deserialization
        return ois.readObject();
    }

    void hashes() throws Exception {
        // ruleid: aca-java-weak-hash
        MessageDigest.getInstance("MD5");
        // ok: aca-java-weak-hash
        MessageDigest.getInstance("SHA-256");
    }

    class TrustAll implements X509TrustManager {
        public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
        // ruleid: aca-java-trust-all-certificates
        public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
        public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
    }

    void security(HttpSecurity http) throws Exception {
        // ruleid: aca-java-spring-csrf-disabled
        http.csrf().disable();
    }
}
