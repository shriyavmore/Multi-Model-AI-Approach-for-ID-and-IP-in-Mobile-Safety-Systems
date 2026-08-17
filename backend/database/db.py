import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import OperationalError

MYSQL_URL = os.getenv("MYSQL_URL", "mysql+pymysql://root:root@localhost:3306/mobile_idps")
SQLITE_URL = "sqlite:///./mobile_idps.db"

Base = declarative_base()

def get_engine():
    """
    Initialize SQLAlchemy database engine.
    - Production Target: Managed PostgreSQL (or MySQL) provided via DATABASE_URL environment variable.
    - Local Development Fallback: SQLite (mobile_idps.db) or local MySQL instance.
    Note: Base.metadata.create_all() initializes initial schemas; for formal production schema updates, database migration tools (e.g. Alembic) should be used.
    """
    db_url = os.getenv("DATABASE_URL")
    if db_url:
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql://", 1)
        try:
            connect_args = {}
            if "sqlite" in db_url:
                connect_args["check_same_thread"] = False
            engine = create_engine(db_url, pool_pre_ping=True, connect_args=connect_args)
            with engine.connect() as conn:
                pass
            print("[DATABASE] Successfully connected to production database via DATABASE_URL.")
            return engine
        except Exception as e:
            print(f"[DATABASE WARNING] DATABASE_URL connection failed ({e}). Falling back to local configuration...")

    try:
        engine = create_engine(MYSQL_URL, pool_pre_ping=True)
        # Test connection
        with engine.connect() as conn:
            pass
        print("[DATABASE] Successfully connected to MySQL database.")
        return engine
    except Exception as e:
        print(f"[DATABASE WARNING] MySQL connection failed ({e}). Falling back to local SQLite database.")
        engine = create_engine(SQLITE_URL, connect_args={"check_same_thread": False})
        return engine

engine = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
