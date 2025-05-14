from app import app
from db import db
from sqlalchemy import text

def run_schema():
    with app.app_context():
        with open("schema.sql") as f:
            schema_sql = f.read()
            for stmt in schema_sql.strip().split(";"):
                if stmt.strip():
                    db.session.execute(text(stmt))
            db.session.commit()

if __name__ == "__main__":
    run_schema()
    print("Database initialized.")