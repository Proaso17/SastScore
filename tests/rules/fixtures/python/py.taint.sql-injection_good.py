def view(request, cursor):
    cursor.execute("SELECT * FROM users WHERE id = %s", [request.args.get("id")])
