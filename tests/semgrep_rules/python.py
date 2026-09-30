# Semgrep rule tests. Lines after a "rule id" annotation must match; lines after an "ok" annotation must not.
import hashlib
import logging
import os
import pickle
import random
import secrets
import ssl
import subprocess
import tempfile

import jwt
import requests
import yaml
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt
from flask import Flask, Markup, render_template_string, request, send_file
from sqlalchemy import text
from werkzeug.utils import secure_filename

app = Flask(__name__)
log = logging.getLogger(__name__)


def sqli(cursor, user_id, name):
    # ruleid: aca-python-sqli-string-built-query
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
    # ruleid: aca-python-sqli-string-built-query
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    # ruleid: aca-python-sqli-string-built-query
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    q = "DELETE FROM users WHERE id = {}".format(user_id)
    # ruleid: aca-python-sqli-string-built-query
    cursor.execute(q)
    # ruleid: aca-python-sqli-string-built-query
    text(f"SELECT * FROM t WHERE x = {name}")
    # ok: aca-python-sqli-string-built-query
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    # ok: aca-python-sqli-string-built-query
    cursor.execute("SELECT 1")


def commands(host):
    # ruleid: aca-python-command-injection
    subprocess.run(f"ping -c 1 {host}", shell=True)
    # ruleid: aca-python-command-injection
    os.system("nslookup " + host)
    # ok: aca-python-command-injection
    subprocess.run(["ping", "-c", "1", host])
    # ok: aca-python-command-injection
    subprocess.run("ls -la", shell=True)
    # ok: aca-python-command-injection
    os.system("uptime")


def code(expr):
    # ruleid: aca-python-code-injection
    eval(expr)
    # ruleid: aca-python-code-injection
    exec(expr)
    # ok: aca-python-code-injection
    eval("1 + 1")


def deserialize(blob, stream):
    # ruleid: aca-python-unsafe-deserialization
    pickle.loads(blob)
    # ruleid: aca-python-unsafe-deserialization
    yaml.load(stream)
    # ok: aca-python-unsafe-deserialization
    yaml.load(stream, Loader=yaml.SafeLoader)
    # ok: aca-python-unsafe-deserialization
    yaml.safe_load(stream)


def hashes(pw):
    # ruleid: aca-python-weak-hash
    hashlib.md5(pw.encode()).hexdigest()
    # ruleid: aca-python-weak-hash
    hashlib.sha1(pw.encode())
    # ok: aca-python-weak-hash
    hashlib.sha256(pw.encode())


def tls(url, ctx):
    # ruleid: aca-python-tls-verification-disabled
    requests.get(url, verify=False)
    # ruleid: aca-python-tls-verification-disabled
    ctx.verify_mode = ssl.CERT_NONE
    # ok: aca-python-tls-verification-disabled
    requests.get(url, timeout=5)


def templates(tpl, html):
    # ruleid: aca-python-ssti
    render_template_string(tpl)
    # ok: aca-python-ssti
    render_template_string("<p>{{ name }}</p>", name=tpl)
    # ruleid: aca-python-xss-markup
    Markup(html)
    # ruleid: aca-python-xss-markup
    mark_safe(html)
    # ok: aca-python-xss-markup
    Markup("<br>")


@app.route("/download")
def download():
    name = request.args.get("file")
    # ruleid: aca-python-path-traversal
    return send_file(os.path.join("/srv/files", name))


@app.route("/download-safe")
def download_safe():
    name = secure_filename(request.args.get("file"))
    # ok: aca-python-path-traversal
    return send_file(os.path.join("/srv/files", name))


@app.route("/read")
def read():
    # ruleid: aca-python-path-traversal
    with open(request.args["path"]) as fh:
        return fh.read()


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    # ruleid: aca-python-ssrf
    return requests.get(url).text


@app.route("/fetch-fixed")
def fetch_fixed():
    # ok: aca-python-ssrf
    return requests.get("https://api.example.com/status").text


def logging_things(user, password, token):
    # ruleid: aca-python-sensitive-data-logged
    logging.info("login %s %s", user, password)
    # ruleid: aca-python-sensitive-data-logged
    log.debug("token=%s", token)
    # ok: aca-python-sensitive-data-logged
    log.info("login for %s", user)
    # ruleid: aca-python-sensitive-data-logged
    print("debug", password)


# ruleid: aca-python-hardcoded-credential
DB_PASSWORD = "S3cr3t-Passw0rd!"
# ruleid: aca-python-hardcoded-credential
app.secret_key = "kd8Fj3kslP0qZm"
# ok: aca-python-hardcoded-credential
API_KEY = "changeme"
# ok: aca-python-hardcoded-credential
PASSWORD = os.environ["PASSWORD"]


# ruleid: aca-python-django-csrf-exempt
@csrf_exempt
def webhook(req):
    return None


def tokens(raw):
    # ruleid: aca-python-jwt-signature-not-verified
    jwt.decode(raw, options={"verify_signature": False})
    # ok: aca-python-jwt-signature-not-verified
    jwt.decode(raw, "key", algorithms=["HS256"])


def temp():
    # ruleid: aca-python-insecure-tempfile
    path = tempfile.mktemp()
    # ok: aca-python-insecure-tempfile
    fd, path = tempfile.mkstemp()
    return path


def randomness():
    # ruleid: aca-python-insecure-random-secret
    reset_token = random.randint(100000, 999999)
    # ruleid: aca-python-insecure-random-secret
    api_key = "".join(random.choice("abcdef0123456789") for _ in range(32))
    # ok: aca-python-insecure-random-secret
    reset_token = secrets.token_urlsafe(32)
    # ok: aca-python-insecure-random-secret
    delay = random.random()
    return reset_token, api_key, delay


if __name__ == "__main__":
    # ruleid: aca-python-flask-debug-enabled
    app.run(debug=True)
    # ok: aca-python-flask-debug-enabled
    app.run(debug=False)
