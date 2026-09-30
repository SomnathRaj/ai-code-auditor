// Semgrep rule tests. Lines after a "rule id" annotation must match; lines after an "ok" annotation must not.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const cp = require("child_process");
const axios = require("axios");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const express = require("express");

const app = express();

function code(expr) {
  // ruleid: aca-js-code-injection
  eval(expr);
  // ruleid: aca-js-code-injection
  const f = new Function("a", expr);
  // ruleid: aca-js-code-injection
  setTimeout("run(" + expr + ")", 10);
  // ok: aca-js-code-injection
  eval("1 + 1");
  // ok: aca-js-code-injection
  setTimeout(() => run(expr), 10);
  // ok: aca-js-code-injection
  setTimeout(tick, 10);
  return f;
}

function commands(host) {
  // ruleid: aca-js-command-injection
  cp.exec("ping -c 1 " + host);
  // ruleid: aca-js-command-injection
  cp.execSync(`nslookup ${host}`);
  // ok: aca-js-command-injection
  cp.execFile("ping", ["-c", "1", host]);
  // ok: aca-js-command-injection
  cp.exec("uptime");
  // ok: aca-js-command-injection
  /a(b)/.exec(host);
  const { exec } = require("child_process");
  // ruleid: aca-js-command-injection
  exec("rm -rf /tmp/" + host);
}

async function sql(db, id, name) {
  // ruleid: aca-js-sqli-string-built-query
  await db.query(`SELECT * FROM users WHERE id = ${id}`);
  // ruleid: aca-js-sqli-string-built-query
  await db.query("SELECT * FROM users WHERE name = '" + name + "'");
  const q = `DELETE FROM users WHERE id = ${id}`;
  // ruleid: aca-js-sqli-string-built-query
  await db.execute(q);
  // ok: aca-js-sqli-string-built-query
  await db.query("SELECT * FROM users WHERE id = ?", [id]);
}

function dom(el, html) {
  // ruleid: aca-js-dom-xss
  el.innerHTML = html;
  // ruleid: aca-js-dom-xss
  document.write(html);
  // ok: aca-js-dom-xss
  el.innerHTML = "<b>static</b>";
  // ok: aca-js-dom-xss
  el.textContent = html;
  // ok: aca-js-dom-xss
  el.innerHTML = DOMPurify.sanitize(html);
}

app.get("/hello", (req, res) => {
  // ruleid: aca-js-express-reflected-xss
  res.send("<h1>Hello " + req.query.name + "</h1>");
});

app.get("/hello-safe", (req, res) => {
  // ok: aca-js-express-reflected-xss
  res.send("<h1>Hello " + escapeHtml(req.query.name) + "</h1>");
});

app.get("/file", (req, res) => {
  const p = path.join(__dirname, "files", req.query.name);
  // ruleid: aca-js-path-traversal
  fs.readFile(p, (err, data) => res.end(data));
});

app.get("/file-safe", (req, res) => {
  const p = path.join(__dirname, "files", path.basename(req.query.name));
  // ok: aca-js-path-traversal
  fs.readFile(p, () => {});
});

app.get("/proxy", async (req, res) => {
  // ruleid: aca-js-ssrf
  const r = await axios.get(req.query.url);
  res.json(r.data);
});

app.get("/proxy-fixed", async (req, res) => {
  // ok: aca-js-ssrf
  const r = await axios.get("https://api.example.com/status");
  res.json(r.data);
});

app.post("/login", async (req, res) => {
  // ruleid: aca-js-nosql-injection
  const user = await User.findOne({ username: req.body.username, password: req.body.password });
  // ok: aca-js-nosql-injection
  const safe = await User.findOne({ username: String(req.body.username) });
  res.json({ user, safe });
});

app.get("/go", (req, res) => {
  // ruleid: aca-js-open-redirect
  res.redirect(req.query.next);
});

app.get("/go-home", (req, res) => {
  // ok: aca-js-open-redirect
  res.redirect("/home");
});

// ruleid: aca-js-tls-verification-disabled
const agent = new https.Agent({ rejectUnauthorized: false });
// ruleid: aca-js-tls-verification-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

// ruleid: aca-js-weak-hash
crypto.createHash("md5").update("x").digest("hex");
// ok: aca-js-weak-hash
crypto.createHash("sha256").update("x").digest("hex");

// ruleid: aca-js-insecure-random-secret
const resetToken = Math.random().toString(36).slice(2);
// ok: aca-js-insecure-random-secret
const jitter = Math.random() * 100;

function logs(user, password, token) {
  // ruleid: aca-js-sensitive-data-logged
  console.log("login", user, password);
  // ruleid: aca-js-sensitive-data-logged
  logger.info("token", token);
  // ok: aca-js-sensitive-data-logged
  console.log("login", user);
}

// ruleid: aca-js-cors-any-origin-with-credentials
app.use(cors({ origin: "*", credentials: true }));
// ok: aca-js-cors-any-origin-with-credentials
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));

// ruleid: aca-js-hardcoded-credential
const apiKey = "sk_live_51Hx9kd8F3kslP0qZm";
// ok: aca-js-hardcoded-credential
const password = process.env.PASSWORD;
// ok: aca-js-hardcoded-credential
const secret = "changeme";
const settings = {
  host: "db.internal",
  // ruleid: aca-js-hardcoded-credential
  dbPassword: "S3cr3t-Passw0rd!",
};

function verify(token, key) {
  // ruleid: aca-js-jwt-weak-verification
  jwt.verify(token, key, { algorithms: ["HS256", "none"] });
  // ok: aca-js-jwt-weak-verification
  jwt.verify(token, key, { algorithms: ["HS256"] });
}

module.exports = { code, commands, sql, dom, logs, verify, agent, resetToken, jitter, apiKey, password, secret };
