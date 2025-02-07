import sqlite3

def get_connection(db_path="database.db"):
    """
    Returns a SQLite connection.
    """
    return sqlite3.connect(db_path, check_same_thread=False)

if __name__ == "__main__":
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT sqlite_version();")
    print("SQLite version:", cursor.fetchone())
    conn.close()
