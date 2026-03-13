import express from "express";
import cors from "cors";
import mysql from "mysql2/promise";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();

const PORT = Number(process.env.PORT || 3001);
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const TRUST_PROXY = process.env.TRUST_PROXY === "true";
const COOLDOWN_HOURS = Number(process.env.COOLDOWN_HOURS || 24);

function requireEnv(name) {
  const value = process.env[name];
  if (!value || !value.trim()) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

const MYSQLHOST = requireEnv("MYSQLHOST");
const MYSQLPORT = Number(process.env.MYSQLPORT || 3306);
const MYSQLUSER = requireEnv("MYSQLUSER");
const MYSQLPASSWORD = requireEnv("MYSQLPASSWORD");
const MYSQLDATABASE = requireEnv("MYSQLDATABASE");

if (TRUST_PROXY) {
  app.set("trust proxy", true);
}

app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
app.use(express.json());

const pool = mysql.createPool({
  host: MYSQLHOST,
  port: MYSQLPORT,
  user: MYSQLUSER,
  password: MYSQLPASSWORD,
  database: MYSQLDATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS profile_views (
      username VARCHAR(255) NOT NULL PRIMARY KEY,
      views INT NOT NULL DEFAULT 0,
      updated_at DATETIME NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS unique_hits (
      id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) NOT NULL,
      visitor_hash VARCHAR(255) NOT NULL,
      last_seen_at DATETIME NOT NULL,
      UNIQUE KEY unique_username_visitor (username, visitor_hash)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS view_logs (
      id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) NOT NULL,
      visitor_hash VARCHAR(255) NOT NULL,
      viewed_at DATETIME NOT NULL
    )
  `);
}

function normalizeUsername(username) {
  return String(username || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "");
}

function escapeXml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function getClientIp(req) {
  const xForwardedFor = req.headers["x-forwarded-for"];

  if (typeof xForwardedFor === "string" && xForwardedFor.length > 0) {
    return xForwardedFor.split(",")[0].trim();
  }

  if (Array.isArray(xForwardedFor) && xForwardedFor.length > 0) {
    return xForwardedFor[0];
  }

  return req.ip || req.socket?.remoteAddress || "unknown";
}

function buildVisitorHash(req, username) {
  const ip = getClientIp(req);
  const userAgent = req.get("user-agent") || "unknown";

  return crypto
    .createHash("sha256")
    .update(`${username}|${ip}|${userAgent}`)
    .digest("hex");
}

function shouldCountNewView(lastSeenAt) {
  if (!lastSeenAt) return true;

  const last = new Date(lastSeenAt).getTime();
  const now = Date.now();
  const diffHours = (now - last) / (1000 * 60 * 60);

  return diffHours >= COOLDOWN_HOURS;
}

async function getProfile(username) {
  const [rows] = await pool.query(
    `
      SELECT username, views, updated_at
      FROM profile_views
      WHERE username = ?
      LIMIT 1
    `,
    [username]
  );

  return rows[0] || null;
}

async function createProfile(username) {
  const now = new Date();

  await pool.query(
    `
      INSERT INTO profile_views (username, views, updated_at)
      VALUES (?, ?, ?)
    `,
    [username, 0, now]
  );

  return await getProfile(username);
}

async function getOrCreateProfile(username) {
  let profile = await getProfile(username);

  if (!profile) {
    profile = await createProfile(username);
  }

  return profile;
}

async function getUniqueHit(username, visitorHash) {
  const [rows] = await pool.query(
    `
      SELECT username, visitor_hash, last_seen_at
      FROM unique_hits
      WHERE username = ? AND visitor_hash = ?
      LIMIT 1
    `,
    [username, visitorHash]
  );

  return rows[0] || null;
}

async function upsertUniqueHit(username, visitorHash, now) {
  await pool.query(
    `
      INSERT INTO unique_hits (username, visitor_hash, last_seen_at)
      VALUES (?, ?, ?)
      ON DUPLICATE KEY UPDATE
        last_seen_at = VALUES(last_seen_at)
    `,
    [username, visitorHash, now]
  );
}

async function insertViewLog(username, visitorHash, now) {
  await pool.query(
    `
      INSERT INTO view_logs (username, visitor_hash, viewed_at)
      VALUES (?, ?, ?)
    `,
    [username, visitorHash, now]
  );
}

async function updateProfileViews(username, views, now) {
  await pool.query(
    `
      UPDATE profile_views
      SET views = ?, updated_at = ?
      WHERE username = ?
    `,
    [views, now, username]
  );
}

async function registerView(username, req) {
  const cleanUsername = normalizeUsername(username);

  if (!cleanUsername) {
    return { error: "Invalid username" };
  }

  const profile = await getOrCreateProfile(cleanUsername);
  const visitorHash = buildVisitorHash(req, cleanUsername);
  const uniqueHit = await getUniqueHit(cleanUsername, visitorHash);
  const now = new Date();

  let nextViews = Number(profile.views || 0);
  let counted = false;

  if (!uniqueHit || shouldCountNewView(uniqueHit.last_seen_at)) {
    nextViews += 1;
    await updateProfileViews(cleanUsername, nextViews, now);
    counted = true;
  }

  await upsertUniqueHit(cleanUsername, visitorHash, now);
  await insertViewLog(cleanUsername, visitorHash, now);

  return {
    username: cleanUsername,
    views: nextViews,
    updatedAt: now.toISOString(),
    counted,
  };
}

async function getProfileData(username) {
  const cleanUsername = normalizeUsername(username);

  if (!cleanUsername) {
    return null;
  }

  return await getOrCreateProfile(cleanUsername);
}

function renderClassicBadgeSvg(username, views) {
  const safeUsername = escapeXml(username);
  const safeViews = escapeXml(String(views));

  const leftText = `${safeUsername} views`;
  const rightText = safeViews;

  const leftWidth = Math.max(130, leftText.length * 8 + 24);
  const rightWidth = Math.max(70, rightText.length * 9 + 20);
  const totalWidth = leftWidth + rightWidth;

  return `
<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="32" role="img" aria-label="${safeUsername} views: ${safeViews}">
  <rect width="${totalWidth}" height="32" fill="#000000"/>
  <rect x="3" y="3" width="${leftWidth - 3}" height="26" fill="#f7f7f7" stroke="#000000" stroke-width="3"/>
  <rect x="${leftWidth}" y="3" width="${rightWidth - 3}" height="26" fill="#f4ce14" stroke="#000000" stroke-width="3"/>
  <g fill="#000000" text-anchor="middle" font-family="Arial, Helvetica, sans-serif" font-size="12" font-weight="900">
    <text x="${leftWidth / 2}" y="21">${leftText}</text>
    <text x="${leftWidth + rightWidth / 2}" y="21">${rightText}</text>
  </g>
</svg>
  `.trim();
}

function renderNeonGradientBadgeSvg(username, views) {
  const safeUsername = escapeXml(username);
  const safeViews = escapeXml(String(views));

  const leftText = `${safeUsername} views`;
  const rightText = safeViews;

  // maliit na size para kapareho ng retro
  const leftWidth = Math.max(130, leftText.length * 8 + 28);
  const rightWidth = Math.max(70, rightText.length * 9 + 20);
  const totalWidth = leftWidth + rightWidth;
  const height = 32;
  const radius = 8;
  const borderSize = 2;

  const cardX = 2;
  const cardY = 2;
  const cardW = totalWidth - 4;
  const cardH = height - 4;

  const contentX = cardX + borderSize;
  const contentY = cardY + borderSize;
  const contentW = cardW - borderSize * 2;
  const contentH = cardH - borderSize * 2;

  const splitX = leftWidth;

  const usernameCenterX = leftWidth / 2;
  const countCenterX = leftWidth + rightWidth / 2;
  const textY = 21;

  return `
<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="${height}" viewBox="0 0 ${totalWidth} ${height}" role="img" aria-label="${safeUsername} views: ${safeViews}">
  <defs>
    <linearGradient id="neonBorderBase" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#ff2f86"/>
      <stop offset="100%" stop-color="#00fff1"/>
    </linearGradient>

    <linearGradient id="neonBorderMove" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#ff2f86"/>
      <stop offset="45%" stop-color="#ff8db8"/>
      <stop offset="100%" stop-color="#00fff1"/>
      <animateTransform
        attributeName="gradientTransform"
        type="translate"
        from="0 -${height}"
        to="0 ${height}"
        dur="2.8s"
        repeatCount="indefinite"
      />
    </linearGradient>

    <filter id="neonGlowOuter" x="-120%" y="-120%" width="340%" height="340%">
      <feGaussianBlur stdDeviation="3" result="blur1"/>
      <feGaussianBlur stdDeviation="6" result="blur2"/>
      <feMerge>
        <feMergeNode in="blur2"/>
        <feMergeNode in="blur1"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>

    <filter id="softTextGlow" x="-120%" y="-120%" width="340%" height="340%">
      <feGaussianBlur stdDeviation="0.7" result="blur"/>
      <feMerge>
        <feMergeNode in="blur"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>

    <mask id="borderMask">
      <rect width="${totalWidth}" height="${height}" fill="black"/>
      <rect
        x="${cardX}"
        y="${cardY}"
        width="${cardW}"
        height="${cardH}"
        rx="${radius}"
        fill="none"
        stroke="white"
        stroke-width="${borderSize * 2}"
      />
    </mask>

    <linearGradient id="textGradientMain" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#ff4f93"/>
      <stop offset="100%" stop-color="#f0b5c7"/>
    </linearGradient>

    <linearGradient id="textGradientSub" x1="0%" y1="100%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#ff8aa9"/>
      <stop offset="100%" stop-color="#9ef9f0"/>
    </linearGradient>

    <clipPath id="contentClip">
      <rect
        x="${contentX}"
        y="${contentY}"
        width="${contentW}"
        height="${contentH}"
        rx="${radius - borderSize}"
      />
    </clipPath>
  </defs>

  <!-- transparent background -->

  <rect
    x="${cardX}"
    y="${cardY}"
    width="${cardW}"
    height="${cardH}"
    rx="${radius}"
    fill="none"
    stroke="url(#neonBorderBase)"
    stroke-width="${borderSize}"
    opacity="0.35"
    filter="url(#neonGlowOuter)"
  />

  <g mask="url(#borderMask)" filter="url(#neonGlowOuter)">
    <rect
      x="${cardX - 8}"
      y="-${height}"
      width="${cardW + 16}"
      height="${height * 3}"
      fill="url(#neonBorderMove)"
      opacity="0.9"
    >
      <animate attributeName="y" from="-${height}" to="0" dur="2.8s" repeatCount="indefinite"/>
    </rect>
  </g>

  <rect
    x="${cardX}"
    y="${cardY}"
    width="${cardW}"
    height="${cardH}"
    rx="${radius}"
    fill="none"
    stroke="url(#neonBorderBase)"
    stroke-width="${borderSize}"
    opacity="0.95"
  />

  <rect
    x="${contentX}"
    y="${contentY}"
    width="${contentW}"
    height="${contentH}"
    rx="${radius - borderSize}"
    fill="#171717"
  />

  <line
    x1="${splitX}"
    y1="${contentY + 4}"
    x2="${splitX}"
    y2="${contentY + contentH - 4}"
    stroke="rgba(132,136,175,0.42)"
    stroke-width="1"
  />

  <g clip-path="url(#contentClip)">
    <text
      x="${usernameCenterX}"
      y="${textY}"
      text-anchor="middle"
      font-family="Arial, Helvetica, sans-serif"
      font-size="12"
      font-weight="900"
      fill="url(#textGradientMain)"
      filter="url(#softTextGlow)"
      lengthAdjust="spacingAndGlyphs"
      textLength="${leftWidth - 18}"
    >
      ${leftText}
    </text>

    <text
      x="${countCenterX}"
      y="${textY}"
      text-anchor="middle"
      font-family="Arial, Helvetica, sans-serif"
      font-size="12"
      font-weight="900"
      fill="url(#textGradientSub)"
      filter="url(#softTextGlow)"
    >
      ${rightText}
    </text>
  </g>
</svg>
  `.trim();
}

function normalizeTheme(theme) {
  const t = String(theme || "retro").toLowerCase();
  if (
    t === "neon" ||
    t === "neonline" ||
    t === "neon-line" ||
    t === "neon-gradient"
  ) {
    return "neon-gradient";
  }
  return "retro";
}

function renderBadgeSvg(username, views, theme = "retro") {
  const normalizedTheme = normalizeTheme(theme);
  if (normalizedTheme === "neon-gradient") {
    return renderNeonGradientBadgeSvg(username, views);
  }
  return renderClassicBadgeSvg(username, views);
}

app.get("/", (_req, res) => {
  res.json({
    name: "GitHub Profile Views Counter API",
    status: "ok",
    endpoints: {
      views: `${BASE_URL}/api/views/:username`,
      badge: `${BASE_URL}/api/badge/:username`,
      badgePreview: `${BASE_URL}/api/badge-preview/:username`,
      profile: `${BASE_URL}/api/profile/:username`,
      top: `${BASE_URL}/api/stats/top`,
      health: `${BASE_URL}/api/health`,
    },
    themes: ["retro", "neon-gradient"],
  });
});

app.get("/api/health", async (_req, res, next) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      ok: true,
      time: new Date().toISOString(),
      database: "connected",
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/views/:username", async (req, res, next) => {
  try {
    const result = await registerView(req.params.username, req);

    if (result.error) {
      return res.status(400).json({ error: result.error });
    }

    return res.json(result);
  } catch (error) {
    next(error);
  }
});

app.get("/api/badge/:username", async (req, res, next) => {
  try {
    const theme = normalizeTheme(req.query.theme);
    const result = await registerView(req.params.username, req);

    if (result.error) {
      return res
        .status(400)
        .type("image/svg+xml")
        .send(renderBadgeSvg("invalid", 0, theme));
    }

    const svg = renderBadgeSvg(result.username, result.views, theme);

    res.setHeader("Content-Type", "image/svg+xml; charset=utf-8");
    res.setHeader(
      "Cache-Control",
      "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0"
    );
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");

    return res.send(svg);
  } catch (error) {
    next(error);
  }
});

app.get("/api/badge-preview/:username", async (req, res, next) => {
  try {
    const theme = normalizeTheme(req.query.theme);
    const profile = await getProfileData(req.params.username);

    if (!profile) {
      return res
        .status(400)
        .type("image/svg+xml")
        .send(renderBadgeSvg("invalid", 0, theme));
    }

    const svg = renderBadgeSvg(
      profile.username,
      Number(profile.views || 0),
      theme
    );

    res.setHeader("Content-Type", "image/svg+xml; charset=utf-8");
    res.setHeader(
      "Cache-Control",
      "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0"
    );
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");

    return res.send(svg);
  } catch (error) {
    next(error);
  }
});

app.get("/api/profile/:username", async (req, res, next) => {
  try {
    const profile = await getProfileData(req.params.username);

    if (!profile) {
      return res.status(400).json({ error: "Invalid username" });
    }

    return res.json({
      username: profile.username,
      views: Number(profile.views || 0),
      updatedAt: new Date(profile.updated_at).toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/stats/top", async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit || 10), 1), 50);

    const [rows] = await pool.query(
      `
        SELECT username, views, updated_at
        FROM profile_views
        ORDER BY views DESC, username ASC
        LIMIT ?
      `,
      [limit]
    );

    return res.json({
      total: rows.length,
      profiles: rows.map((row, index) => ({
        rank: index + 1,
        username: row.username,
        views: Number(row.views || 0),
        updatedAt: new Date(row.updated_at).toISOString(),
      })),
    });
  } catch (error) {
    next(error);
  }
});

app.use((req, res) => {
  res.status(404).json({
    error: "Route not found",
    path: req.originalUrl,
  });
});

app.use((err, _req, res, _next) => {
  console.error("SERVER ERROR:", err);

  res.status(500).json({
    error: "Internal server error",
    details: err.message,
  });
});

async function startServer() {
  try {
    console.log("Connecting to MySQL...");
    await pool.query("SELECT 1");
    console.log("MySQL connected.");

    console.log("Initializing tables...");
    await initDb();
    console.log("Tables ready.");

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Health check: ${BASE_URL}/api/health`);
    });
  } catch (error) {
    console.error("FAILED TO START SERVER:", error);
    process.exit(1);
  }
}

startServer();