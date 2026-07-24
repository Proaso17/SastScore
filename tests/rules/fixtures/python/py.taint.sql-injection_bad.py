def view(request, cursor):
    query = "SELECT * FROM users WHERE id = " + request.args.get("id")
    cursor.execute(query)
