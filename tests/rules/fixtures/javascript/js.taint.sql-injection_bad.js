function handler(req, conn) {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  conn.query(query);
}

module.exports = { handler };
