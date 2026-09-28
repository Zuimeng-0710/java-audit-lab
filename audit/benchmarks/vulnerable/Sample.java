import java.io.File;
class Sample {
  String API_KEY = "demo-secret-value";
  void sql(java.sql.Statement s, String input) throws Exception { s.executeQuery("SELECT * FROM t WHERE x=" + input); }
  void cmd(String command) throws Exception { Runtime.getRuntime().exec(command); }
  void path(String fileName) { new File("data/" + fileName); }
  void xml() { javax.xml.parsers.DocumentBuilderFactory.newInstance(); }
  void deserialize(java.io.ObjectInputStream input) throws Exception { input.readObject(); }
  void request(String url) throws Exception { new java.net.URL(url).openConnection(); }
  void expression(Parser parser, String expression) { parser.parseExpression(expression); }
  void hash() throws Exception { java.security.MessageDigest.getInstance("MD5"); }
  interface Parser { Object parseExpression(String value); }
}
