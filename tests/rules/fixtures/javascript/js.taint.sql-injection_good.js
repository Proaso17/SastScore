function handler(req, conn) {
  conn.query("SELECT * FROM users WHERE id = ?", [req.query.id]);
}

module.exports = { handler };
