import os
import pickle
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)
API_KEY = "FAKE9f8e7d6c5b4a39281706f5e4d3c2b1a0Zq"


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr")))


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return subprocess.run("nslookup " + request.args["host"], shell=True, capture_output=True).stdout


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)
    cfg = yaml.load(request.data)
    return str(obj) + str(cfg)


@app.route("/user")
def user():
    conn = sqlite3.connect("app.db")
    user_id = request.args.get("id")
    return str(conn.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchall())


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
