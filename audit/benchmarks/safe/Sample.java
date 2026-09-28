class Sample {
  void sql(java.sql.Connection c, String input) throws Exception {
    var statement = c.prepareStatement("SELECT * FROM t WHERE x = ?");
    statement.setString(1, input);
  }
}
