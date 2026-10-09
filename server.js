
import express from "express";
import pg from "pg";
import crypto from "node:crypto";

const app = express();
app.use(express.json({ limit: "10kb" }));

const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("railway")
    ? { rejectUnauthorized: false }
    : undefined
});

const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const hashKey = (key) =>
  crypto.createHash("sha256").update(key).digest("hex");

app.get("/", (_req, res) => {
  res.json({ status: "healthy", service: "huy-key-server" });
});

app.post("/admin/keys", async (req, res) => {
  if (!ADMIN_TOKEN ||
      req.get("authorization") !== `Bearer ${ADMIN_TOKEN}`) {
    return res.status(401).json({ error: "UNAUTHORIZED" });
  }

  const days = Number(req.body?.days);
  if (!Number.isInteger(days) || days < 1 || days > 3650) {
    return res.status(400).json({ error: "days must be 1-3650" });
  }

  try {
    const key = "HUY-" + crypto.randomBytes(18).toString("hex");
    const expires = new Date(Date.now() + days * 86400000);

    await pool.query(
      `INSERT INTO license_keys (key_hash, expires_at)
       VALUES ($1, $2)`,
      [hashKey(key), expires]
    );

    res.json({ key, expires_at: expires.toISOString() });
  } catch {
    res.status(500).json({ error: "DATABASE_ERROR" });
  }
});

app.post("/api/validate", async (req, res) => {
  const key = typeof req.body?.key === "string"
    ? req.body.key.trim()
    : "";

  if (!key || key.length > 200) {
    return res.status(400).json({ valid: false });
  }

  try {
    const result = await pool.query(
      `SELECT expires_at, revoked
       FROM license_keys WHERE key_hash = $1`,
      [hashKey(key)]
    );

    const row = result.rows[0];
    const valid = !!row &&
      !row.revoked &&
      new Date(row.expires_at).getTime() > Date.now();

    res.json({
      valid,
      expires_at: row?.expires_at ?? null
    });
  } catch {
    res.status(500).json({ error: "DATABASE_ERROR" });
  }
});

app.post("/admin/revoke", async (req, res) => {
  if (!ADMIN_TOKEN ||
      req.get("authorization") !== `Bearer ${ADMIN_TOKEN}`) {
    return res.status(401).json({ error: "UNAUTHORIZED" });
  }

  const key = typeof req.body?.key === "string"
    ? req.body.key.trim()
    : "";

  if (!key || key.length > 200) {
    return res.status(400).json({ error: "INVALID_KEY" });
  }

  try {
    const result = await pool.query(
      `UPDATE license_keys SET revoked = TRUE
       WHERE key_hash = $1`,
      [hashKey(key)]
    );

    res.json({ revoked: result.rowCount === 1 });
  } catch {
    res.status(500).json({ error: "DATABASE_ERROR" });
  }
});

async function start() {
  if (!process.env.DATABASE_URL || !ADMIN_TOKEN) {
    throw new Error("Missing DATABASE_URL or ADMIN_TOKEN");
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS license_keys (
      key_hash TEXT PRIMARY KEY,
      expires_at TIMESTAMPTZ NOT NULL,
      revoked BOOLEAN NOT NULL DEFAULT FALSE
    )
  `);

  const port = Number(process.env.PORT || 3000);
  app.listen(port, "0.0.0.0", () =>
    console.log("Key server listening on", port)
  );
}

start().catch((err) => {
  console.error("Startup failed:", err.message);
  process.exit(1);
});
      
