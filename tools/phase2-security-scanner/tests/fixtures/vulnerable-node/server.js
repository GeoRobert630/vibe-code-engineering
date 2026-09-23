const express = require("express");
const { exec } = require("child_process");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
const pool = new Pool();
app.use(cors({ origin: "*" }));

app.get("/calc", (req, res) => {
  const result = eval(req.query.expr);
  res.send(String(result));
});

app.get("/ls", (req, res) => {
  exec(`ls -la ${req.query.dir}`, (err, stdout) => res.send(stdout));
});

app.get("/user", async (req, res) => {
  const rows = await pool.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
  res.json(rows);
});

app.post("/login", (req, res) => {
  res.cookie("session", "abc", { httpOnly: false, secure: false });
  res.send("ok");
});

app.listen(3000);
