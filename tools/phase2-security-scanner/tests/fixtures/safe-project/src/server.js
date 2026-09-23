const express = require("express");
const { execFile } = require("node:child_process");
const path = require("node:path");

const app = express();
const ALLOWED_ORIGINS = new Set(["https://app.example.com"]);
const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

app.use((req, res, next) => {
  const origin = req.get("origin");
  if (origin && ALLOWED_ORIGINS.has(origin)) res.set("Access-Control-Allow-Origin", origin);
  next();
});

app.get("/date", (req, res) => {
  const m = DATE_RE.exec(String(req.query.d || ""));
  res.json({ valid: Boolean(m) });
});

app.get("/version", (_req, res) => {
  execFile("git", ["--version"], (err, stdout) => res.send(err ? "unknown" : stdout));
});

async function getUser(db, id) {
  return db.query("SELECT id, name FROM users WHERE id = $1", [id]);
}

const apiKey = process.env.PAYMENTS_API_KEY;

module.exports = { app, getUser, apiKey, root: path.join(__dirname, "static") };
