"""MongoDB connection. One MongoClient per process (PyMongo pools connections)."""
from flask import Flask, current_app
from pymongo import MongoClient
from pymongo.database import Database


def init_mongo(app: Flask) -> None:
    client = MongoClient(
        app.config["MONGODB_URI"],
        serverSelectionTimeoutMS=app.config["MONGO_TIMEOUT_MS"],
        tz_aware=True,
        uuidRepresentation="standard",
        appname="ai-code-auditor",
    )
    app.extensions["mongo_client"] = client
    app.extensions["mongo_db"] = client[app.config["MONGODB_DATABASE"]]


def get_client() -> MongoClient:
    return current_app.extensions["mongo_client"]


def get_db() -> Database:
    return current_app.extensions["mongo_db"]


def supports_transactions() -> bool:
    """Multi-document transactions need a replica set or sharded cluster."""
    cached = current_app.extensions.get("mongo_tx")
    if cached is None:
        hello = get_client().admin.command("hello")
        cached = bool(hello.get("setName")) or hello.get("msg") == "isdbgrid"
        current_app.extensions["mongo_tx"] = cached
    return cached


def run_in_transaction(callback):
    """Run callback(session) in a transaction when supported, else callback(None).

    Callers must order their writes so that a failure part-way through leaves
    no dangling data when there is no transaction (see PRD §41.1).
    """
    if not supports_transactions():
        return callback(None)
    with get_client().start_session() as session:
        return session.with_transaction(callback)
