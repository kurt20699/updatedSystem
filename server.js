const express = require("express");
const cors = require("cors");
const path = require("path");
const { Pool } = require("pg");
const crypto = require("crypto");
const Permissions = require("./permissions.js");
require("dotenv").config();

  const app = express();
  const port = process.env.PORT || 3001;
  const supabaseDbUrl = process.env.DATABASE_URL || process.env.SUPABASE_DATABASE_URL;
  
// const primaryDbUrl = process.env.DATABASE_URL || process.env.NEON_DATABASE_URL;
//
// if (!primaryDbUrl) {
//   console.error("Missing DATABASE_URL (or NEON_DATABASE_URL) in environment.");
//   process.exit(1);
// }

if (!supabaseDbUrl) {
  console.error("Missing DATABASE_URL (or SUPABASE_DATABASE_URL) in environment.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: supabaseDbUrl,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 30000,
  idleTimeoutMillis: 60000,
  query_timeout: 30000
});

// ✅ Force every pooled connection to interpret/display timestamptz values
// (navigated_at, created_at, etc.) in Philippine local time instead of the
// server's default (UTC on Supabase). timestamptz always stores the correct
// UTC instant internally — this only affects how it's read back out via
// EXTRACT(), NOW()::text, direct SELECTs, etc.
// Using pool.on('connect', ...) instead of the connectionString's `options`
// param because Supabase's pooler (pgbouncer, transaction mode) can silently
// drop startup options — this runs explicitly on every new connection.
pool.on('connect', (client) => {
  client.query("SET TIME ZONE 'Asia/Manila'").catch(err => {
    console.error('Failed to set session timezone:', err.message);
  });
});

const resetSessions = new Map();

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname)));

app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

function formatRegistrationMessage({ name, userId, role, verificationLink }) {
  return [
    "Welcome to PRMSU Smart Campus Navigator!",
    `Name: ${name}`,
    `User ID: ${userId}`,
    `Role: ${role}`,
    "",
    "Please verify your email address by clicking the link below:",
    verificationLink,
    "",
    "This link expires in 24 hours. If you did not create this account, you can safely ignore this email."
  ].join("\n");
}

const bcrypt = require("bcryptjs");
const BCRYPT_ROUNDS = 12;

function legacySha256Hash(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

async function hashPassword(password) {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

function isBcryptHash(hash) {
  return typeof hash === "string" && /^\$2[aby]\$/.test(hash);
}

async function verifyPassword(password, storedHash) {
  if (isBcryptHash(storedHash)) {
    return { valid: await bcrypt.compare(password, storedHash), needsMigration: false };
  }
  const valid = legacySha256Hash(password) === storedHash;
  return { valid, needsMigration: valid };
}

async function migratePasswordHash(userId, plaintextPassword) {
  try {
    const newHash = await hashPassword(plaintextPassword);
    await pool.query(
      `UPDATE users SET password_hash = $1 WHERE LOWER(user_id) = LOWER($2)`,
      [newHash, userId]
    );
  } catch (err) {
    console.error("Password hash migration failed for", userId, err.message);
  }
}

function generateOtpCode() {
  return String(crypto.randomInt(100000, 1000000));
}

// ── Logging helpers: notification_logs / audit_logs / chat_logs ──
async function logNotification({ userId, channel, recipient, subject, message, status, errorDetail, context }) {
  try {
    await pool.query(
      `INSERT INTO notification_logs (user_id, channel, recipient, subject, message, status, error_detail, context)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [userId || null, channel, recipient, subject || null, message || null, status, errorDetail || null, context || null]
    );
  } catch (err) {
    console.error("notification_logs insert failed:", err.message);
  }
}

async function logAudit({ adminUserId, action, entityType, entityId, details, ipAddress }) {
  try {
    await pool.query(
      `INSERT INTO audit_logs (admin_user_id, action, entity_type, entity_id, details, ip_address)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [
        adminUserId || null,
        action,
        entityType,
        entityId != null ? String(entityId) : null,
        details ? JSON.stringify(details) : null,
        ipAddress || null
      ]
    );
  } catch (err) {
    console.error("audit_logs insert failed:", err.message);
  }
}

async function logChat({ userId, question, reply, wasRateLimited, errorDetail }) {
  try {
    await pool.query(
      `INSERT INTO chat_logs (user_id, question, reply, was_rate_limited, error_detail)
       VALUES ($1,$2,$3,$4,$5)`,
      [userId || null, question, reply || null, wasRateLimited === true, errorDetail || null]
    );
  } catch (err) {
    console.error("chat_logs insert failed:", err.message);
  }
}

function generateResetToken() {
  return crypto.randomBytes(24).toString("hex");
}

function normalizeResetEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeResetPhoneDigits(value) {
  return String(value || "").replace(/\D/g, "");
}

function getResetSessionKey(method, identifier) {
  const normalizedMethod = String(method || "").trim().toLowerCase();
  if (normalizedMethod === "sms") {
    return `${normalizedMethod}:${normalizeResetPhoneDigits(identifier)}`;
  }
  return `${normalizedMethod}:${normalizeResetEmail(identifier)}`;
}

// ── Role-aware guard — looks up the caller's role from DB (or accepts an
// explicit ?role= for logged-out/visitor flows) and blocks disallowed
// building types. Fails closed: unknown/missing user => VISITOR rules. ──
async function getCallerRole(req) {
  const userId = req.body?.userId || req.query?.userId;
  if (!userId) return Permissions.ROLES.VISITOR;
  try {
    const result = await pool.query(
      `SELECT role FROM users WHERE LOWER(user_id) = LOWER($1)`,
      [userId]
    );
    return result.rows.length ? result.rows[0].role : Permissions.ROLES.VISITOR;
  } catch {
    return Permissions.ROLES.VISITOR;
  }
}

// userId and verifying against the DB (same as /api/auth/update-photo) ──
async function requireAdmin(req, res, next) {
  const adminUserId = req.body?.adminUserId || req.query?.adminUserId;
  if (!adminUserId) {
    return res.status(401).json({ ok: false, error: "Missing adminUserId." });
  }
  try {
    const result = await pool.query(
      `SELECT role FROM users WHERE LOWER(user_id) = LOWER($1)`,
      [adminUserId]
    );
    if (!result.rows.length || result.rows[0].role !== "ADMIN") {
      return res.status(403).json({ ok: false, error: "Admin access required." });
    }
    next();
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
}

function formatResetOtpMessage({ name, otp, expiresMinutes }) {
  return [
    "PRMSU Navigator Password Reset",
    `Hello ${name},`,
    `Your one-time password (OTP) is: ${otp}`,
    `This code expires in ${expiresMinutes} minutes.`,
    "If you did not request a password reset, please ignore this message."
  ].join("\n");
}

function formatPasswordChangedMessage({ name }) {
  return [
    "PRMSU Navigator Password Updated",
    `Hello ${name},`,
    "Your password has been updated successfully.",
    "If you did not make this change, contact support immediately."
  ].join("\n");
}

function normalizePhPhoneNumber(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  const digits = raw.replace(/[^0-9+]/g, "");
  if (digits.startsWith("+63")) return digits;
  if (digits.startsWith("63")) return `+${digits}`;
  if (digits.startsWith("0")) return `+63${digits.slice(1)}`;
  return digits;
}

async function sendBrevoEmail({ toEmail, toName, subject, textBody }) {
  const apiKey = process.env.BREVO_API_KEY;
  const senderEmail = process.env.BREVO_SENDER_EMAIL;
  const senderName = process.env.BREVO_SENDER_NAME || "PRMSU Navigator";
  if (!apiKey || !senderEmail || !toEmail) {
    return { sent: false, reason: "Brevo not configured" };
  }

  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "api-key": apiKey
    },
    body: JSON.stringify({
      sender: { email: senderEmail, name: senderName },
      to: [{ email: toEmail, name: toName || toEmail }],
      subject,
      textContent: textBody
    })
  });

  if (!response.ok) {
    const details = await response.text();
    throw new Error(`Brevo send failed: ${response.status} ${details}`);
  }
  return { sent: true };
}

async function sendPhilSms({ phone, message }) {
  return { sent: false, reason: "SMS disabled" };
  /*
  const apiKey = process.env.PHILSMS_API_KEY;
  const senderId = process.env.PHILSMS_SENDER || "PHILSMS";
  const endpoint = process.env.PHILSMS_ENDPOINT || "https://app.philsms.com/api/v3/sms/send";
  const normalizedPhone = normalizePhPhoneNumber(phone);
  if (!apiKey || !normalizedPhone) {
    return { sent: false, reason: "PhilSMS not configured" };
  }

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Bearer ${apiKey}`
    },
    body: new URLSearchParams({
      recipient: normalizedPhone,
      sender_id: senderId,
      type: "plain",
      message
    }).toString()
  });

  if (!response.ok) {
    const details = await response.text();
    throw new Error(`PhilSMS send failed: ${response.status} ${details}`);
  }
  return { sent: true };
  */
}

// ══════════════════════════════════════════
// 🤖 GEMINI CHAT ASSISTANT
// ══════════════════════════════════════════

const GEMINI_MODEL = "gemini-2.5-flash"; // free-tier model — do not swap to a Pro variant
const GEMINI_URL = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;

// Base behavior instructions — role/location specifics are appended per-request.
const CHAT_SYSTEM_PROMPT_BASE = `You are a helpful assistant for the PRMSU Smart Campus Navigator app.
Help users understand how to use the map, find buildings and rooms, get directions,
and use features like the virtual tour. Keep answers short and friendly.
Do not discuss unrelated topics, and never ask for or repeat personal information.`;

// Human-readable feature names for messaging when a role lacks a feature.
const FEATURE_LABELS = {
  saveLocations:   "saving locations",
  routeHistory:    "route history",
  multiStop:       "multi-stop navigation",
  roomInstructor:  "room instructor info",
  searchRooms:     "room search"
};

// Builds the role-scoped context injected into the system prompt.
// This is the ONLY source of building/room data the model receives —
// restricted buildings are simply never sent, so the model can't recommend,
// confirm, or describe them, even if asked directly.
async function buildChatContext(role) {
  const config = Permissions.getRoleConfig(role);
  const enabledFeatures  = Object.entries(config.features || {}).filter(([, v]) => v).map(([k]) => FEATURE_LABELS[k] || k);
  const disabledFeatures = Object.entries(config.features || {}).filter(([, v]) => !v).map(([k]) => FEATURE_LABELS[k] || k);

  let buildingLines = [];
  try {
    const result = await pool.query('SELECT name, short_name, type FROM buildings ORDER BY name');
    buildingLines = result.rows
      .filter(b => Permissions.assertLocationTypeAllowed(role, b.type))
      .map(b => `- ${b.name} (${b.short_name}), type: ${b.type}`);
  } catch (err) {
    console.warn('Chat context: could not load buildings from DB:', err.message);
  }

  const buildingsBlock = buildingLines.length
    ? buildingLines.join('\n')
    : '(No building data currently available.)';

  return [
    `The current user's role is: ${role}.`,
    `Only the following buildings/locations exist for this conversation — do not mention, confirm, or describe any building not on this list, even if asked directly by name. If asked about something not listed, say it isn't available for their account type:`,
    buildingsBlock,
    enabledFeatures.length  ? `Features this user CAN use: ${enabledFeatures.join(', ')}.` : '',
    disabledFeatures.length ? `Features this user CANNOT use: ${disabledFeatures.join(', ')}. If asked about these, explain they require a different account type.` : ''
  ].filter(Boolean).join('\n\n');
}

function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Deterministic pre-check: if the user's message names a building the role
// isn't allowed to see, short-circuit with a refusal WITHOUT calling Gemini.
// This is the actual enforcement boundary — the system prompt alone is not
// reliable, since the model may already "know" about a real building from
// training data regardless of what context it was given.
async function findRestrictedBuildingMention(message, role) {
  try {
    const result = await pool.query('SELECT name, short_name, type FROM buildings');
    const lowerMessage = message.toLowerCase();

    for (const b of result.rows) {
      if (Permissions.assertLocationTypeAllowed(role, b.type)) continue; // allowed, skip

      const candidates = [b.name, b.short_name].filter(Boolean);
      for (const candidate of candidates) {
        const pattern = new RegExp(`\\b${escapeRegExp(candidate.toLowerCase())}\\b`, 'i');
        if (pattern.test(lowerMessage)) {
          return b; // restricted building mentioned by name
        }
      }
    }
    return null;
  } catch (err) {
    console.warn('Restricted building check failed:', err.message);
    return null; // fail-open on DB error is acceptable here — buildChatContext
                 // will also fail to load buildings in that case, so the model
                 // has no building data to leak either way.
  }
}

async function callGemini(userMessage, role) {
  const roleContext = await buildChatContext(role);
  const systemInstruction = `${CHAT_SYSTEM_PROMPT_BASE}\n\n${roleContext}`;

  const response = await fetch(`${GEMINI_URL}?key=${process.env.GEMINI_API_KEY}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ parts: [{ text: userMessage }] }],
      systemInstruction: { parts: [{ text: systemInstruction }] }
    })
  });

  const data = await response.json();

  if (!response.ok) {
    const errMsg = data.error?.message || "";
    const isRateLimited = response.status === 429 || errMsg.includes("RESOURCE_EXHAUSTED");
    const err = new Error(errMsg || "Gemini API error");
    err.status = response.status;
    err.isRateLimited = isRateLimited;
    throw err;
  }

  return data.candidates?.[0]?.content?.parts?.[0]?.text
    || "Sorry, I couldn't come up with a response for that. Try rephrasing your question.";
}

app.post("/api/chat", async (req, res) => {
  const { message, userId } = req.body || {};
  if (!message || typeof message !== "string" || !message.trim()) {
    return res.status(400).json({ ok: false, error: "Message is required." });
  }

  if (!process.env.GEMINI_API_KEY) {
    return res.status(503).json({ ok: false, error: "Chat assistant is not configured." });
  }

  const trimmedMessage = message.trim();
  const role = await getCallerRole(req);

  // 🔒 Deterministic RBAC check — runs before Gemini, cannot be talked around.
  const restricted = await findRestrictedBuildingMention(trimmedMessage, role);
  if (restricted) {
    const denialReply = `Sorry, information about ${restricted.name} isn't available for your account type.`;
    await logChat({ userId, question: trimmedMessage, reply: denialReply });
    return res.json({ ok: true, reply: denialReply });
  }

  try {
    const reply = await callGemini(trimmedMessage, role);
    await logChat({ userId, question: trimmedMessage, reply });
    return res.json({ ok: true, reply });
  } catch (err) {
    console.error("Gemini chat error:", err.status, err.message);

    if (err.isRateLimited) {
      const fallbackReply = "I'm getting a lot of questions right now — please try again in a few minutes, or check the app's help sections directly.";
      await logChat({ userId, question: trimmedMessage, reply: fallbackReply, wasRateLimited: true });
      return res.json({ ok: true, reply: fallbackReply });
    }

    await logChat({ userId, question: trimmedMessage, errorDetail: err.message });
    return res.status(500).json({ ok: false, error: "Something went wrong on my end. Please try again shortly." });
  }
});

app.get("/api/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.status(200).json({
      ok: true,
      databases: {
        supabase: "connected"
      }
    });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post("/api/notify-registration", async (req, res) => {
  const { userId, name, email, phone, role, password } = req.body || {};
  if (!userId || !name || !email || !phone || !role || !password) {
    return res.status(400).json({ ok: false, error: "Missing required registration notification fields." });
  }

  const subject = "PRMSU Navigator Registration Confirmation";
  const fullMessage = formatRegistrationMessage({ name, userId, role, password });
  // const smsMessage = `PRMSU Reg OK. ID:${userId} Role:${role} Pass:${password}`; // SMS disabled

  const result = {
    ok: true,
    channels: {
      email: "skipped"
      // sms: "skipped" // SMS disabled
    }
  };

  try {
    const emailResult = await sendBrevoEmail({
      toEmail: email,
      toName: name,
      subject,
      textBody: fullMessage
    });
    result.channels.email = emailResult.sent ? "sent" : emailResult.reason;
  } catch (error) {
    result.channels.email = `failed: ${error.message}`;
    result.ok = false;
  }

  /* SMS DISABLED
  try {
    const smsResult = await sendPhilSms({
      phone,
      message: smsMessage
    });
    result.channels.sms = smsResult.sent ? "sent" : smsResult.reason;
  } catch (error) {
    result.channels.sms = `failed: ${error.message}`;
    result.ok = false;
  }
  */

  return res.status(result.ok ? 200 : 500).json(result);
});

app.post("/api/auth/register", async (req, res) => {
  const { name, email, role, password, idDocument } = req.body || {};
  if (!name || !email || !role || !password) {
    return res.status(400).json({ ok: false, error: "Missing required registration fields." });
  }

  const normalizedRole = String(role).toUpperCase();
  // ✅ VISITOR is no longer a registerable role — visitors get in via the
  // QR check-in / "Continue as Guest" flow (/api/checkin, /api/checkin/guest),
  // which issues a role-less, password-less VISITOR session directly.
  // Registering a VISITOR account here would be redundant with that flow.
  if (!["STUDENT", "EMPLOYEE"].includes(normalizedRole)) {
    return res.status(400).json({ ok: false, error: "Invalid role." });
  }

  // ✅ Student ID / Employee ID upload is mandatory — this is what the
  // Admin reviews in the Pending Approvals list before the account is
  // allowed to log in. Stored the same way profile photos already are
  // (base64 data URL string), capped at 4MB.
  if (!idDocument || typeof idDocument !== "string") {
    return res.status(400).json({ ok: false, error: "Please upload a photo of your Student ID or Employee ID." });
  }
  if (idDocument.length > 4 * 1024 * 1024) {
    return res.status(400).json({ ok: false, error: "ID photo is too large. Please upload a file under 4MB." });
  }

  const passwordHash = await hashPassword(password);

  // Generate a secure email verification token valid for 24 hours
  const verificationToken = crypto.randomBytes(32).toString("hex");
  const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

  try {
    const insertResult = await pool.query(
      `INSERT INTO users (full_name, email, phone, role, password_hash, email_verified, verification_token, verification_token_expires, id_document, verification_status)
      VALUES ($1, $2, $3, $4, $5, FALSE, $6, $7, $8, 'pending')
      RETURNING user_id, full_name, email, phone, role, created_at`,
      [name.trim(), email.trim().toLowerCase(), null, normalizedRole, passwordHash, verificationToken, verificationExpires, idDocument]
    );

    const user = insertResult.rows[0];

    const appBaseUrl = process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 3001}`;
    const verificationLink = `${appBaseUrl}/api/auth/verify-email?token=${verificationToken}`;

    const notifyPayload = {
      userId: user.user_id,
      name: user.full_name,
      email: user.email,
      role: user.role,
      verificationLink
    };

    const subject = "Verify your PRMSU Navigator email address";
    const fullMessage = formatRegistrationMessage(notifyPayload);
    const channels = { email: "skipped" };

    try {
      const emailResult = await sendBrevoEmail({
        toEmail: notifyPayload.email,
        toName: notifyPayload.name,
        subject,
        textBody: fullMessage
      });
      channels.email = emailResult.sent ? "sent" : emailResult.reason;
      await logNotification({
        userId: user.user_id, channel: "email", recipient: notifyPayload.email,
        subject, message: fullMessage, status: emailResult.sent ? "sent" : "skipped",
        context: "registration"
      });
    } catch (error) {
      channels.email = `failed: ${error.message}`;
      await logNotification({
        userId: user.user_id, channel: "email", recipient: notifyPayload.email,
        subject, message: fullMessage, status: "failed", errorDetail: error.message,
        context: "registration"
      });
    }

    return res.status(201).json({
      ok: true,
      user: {
        userId: user.user_id,
        name: user.full_name,
        email: user.email,
        phone: user.phone,
        role: user.role
      },
      notifications: channels
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ ok: false, error: "Email or user ID already exists." });
    }
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.get("/api/auth/verify-email", async (req, res) => {
  const { token } = req.query;
  if (!token) {
    return res.status(400).send("Invalid verification link.");
  }

  try {
    const result = await pool.query(
      `SELECT user_id, email_verified, verification_token_expires
       FROM users WHERE verification_token = $1 LIMIT 1`,
      [token]
    );

    if (!result.rows.length) {
      return res.status(400).send(`
        <html><body style="font-family:sans-serif;text-align:center;padding:60px">
          <h2>❌ Invalid verification link.</h2>
          <p>This link is invalid or has already been used.</p>
          <a href="/">Back to app</a>
        </body></html>
      `);
    }

    const user = result.rows[0];

    if (user.email_verified) {
      return res.send(`
        <html><body style="font-family:sans-serif;text-align:center;padding:60px">
          <h2>✅ Email already verified.</h2>
          <p>Your account is already active. You can log in.</p>
          <a href="/">Go to app</a>
        </body></html>
      `);
    }

    if (new Date() > new Date(user.verification_token_expires)) {
      return res.status(400).send(`
        <html><body style="font-family:sans-serif;text-align:center;padding:60px">
          <h2>⏰ Verification link expired.</h2>
          <p>Please register again or contact support.</p>
          <a href="/">Back to app</a>
        </body></html>
      `);
    }

    await pool.query(
      `UPDATE users
       SET email_verified = TRUE, verification_token = NULL, verification_token_expires = NULL
       WHERE user_id = $1`,
      [user.user_id]
    );

    return res.send(`
      <html><body style="font-family:sans-serif;text-align:center;padding:60px">
        <h2>✅ Email verified successfully!</h2>
        <p>Your account is now active. You can log in to PRMSU Navigator.</p>
        <a href="/">Go to app</a>
      </body></html>
    `);
  } catch (error) {
    return res.status(500).send("Server error. Please try again later.");
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { identifier, password } = req.body || {};
  if (!identifier || !password) {
    return res.status(400).json({ ok: false, error: "User ID and password are required." });
  }

  const normalizedIdentifier = String(identifier).trim().toLowerCase();

  try {
    const result = await pool.query(
      `SELECT user_id, full_name, email, role, password_hash, email_verified, verification_status
      FROM users
      WHERE (LOWER(email) = $1 OR LOWER(user_id) = $1)
      LIMIT 1`,
      [normalizedIdentifier]
    );

    if (!result.rows.length) {
      return res.status(401).json({ ok: false, error: "Invalid user ID or password." });
    }

    const user = result.rows[0];
    const { valid, needsMigration } = await verifyPassword(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ ok: false, error: "Invalid user ID or password." });
    }

    // Block login if email has not been verified yet
    if (!user.email_verified) {
      return res.status(403).json({ ok: false, error: "Please verify your email address before logging in. Check your inbox for the verification link." });
    }

    // ✅ Block login until an Admin has verified the uploaded Student/Employee ID
    if (user.verification_status === "pending") {
      return res.status(403).json({ ok: false, error: "Your account is pending admin verification. You'll be able to log in once it's approved." });
    }
    if (user.verification_status === "rejected") {
      return res.status(403).json({ ok: false, error: "Your registration was not approved. Please contact the campus admin for assistance." });
    }
    if (needsMigration) {
      await migratePasswordHash(user.user_id, password);
    }
    return res.json({
      ok: true,
      user: {
        userId: user.user_id,
        name: user.full_name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.post("/api/auth/forgot/request", async (req, res) => {
  const { identifier, method } = req.body || {};
  if (!identifier) {
    return res.status(400).json({ ok: false, error: "Email or phone number is required." });
  }

  // SMS DISABLED — only 'email' is accepted now
  const normalizedMethod = (method || "email").toLowerCase();
  if (!['email' /*, 'sms' */].includes(normalizedMethod)) {
    return res.status(400).json({ ok: false, error: "Invalid reset method." });
  }

  try {
    const normalizedIdentifier = normalizedMethod === "sms"
      ? normalizeResetPhoneDigits(identifier)
      : normalizeResetEmail(identifier);
    if (!normalizedIdentifier) {
      const errorLabel = normalizedMethod === 'email' ? 'Email' : 'Phone number';
      return res.status(400).json({ ok: false, error: `${errorLabel} is required.` });
    }

    const result = await pool.query(
      `SELECT user_id, full_name, email, phone
      FROM users
      WHERE ${normalizedMethod === 'email'
        ? 'LOWER(email)'
        : "regexp_replace(COALESCE(phone, ''), '[^0-9]', '', 'g')"} = $1
      LIMIT 1`,
      [normalizedIdentifier]
    );

    if (!result.rows.length) {
      const errorLabel = normalizedMethod === 'email' ? 'Email' : 'Phone number';
      return res.status(404).json({ ok: false, error: `${errorLabel} not found.` });
    }

    const user = result.rows[0];
    const otp = generateOtpCode();
    const expiresMinutes = 5;
    const expiresAt = Date.now() + expiresMinutes * 60 * 1000;

    if (normalizedMethod === "email") {
      const otpTextBody = formatResetOtpMessage({ name: user.full_name, otp, expiresMinutes });
      const emailResult = await sendBrevoEmail({
        toEmail: user.email,
        toName: user.full_name,
        subject: "PRMSU Navigator Password Reset Code",
        textBody: otpTextBody
      });
      await logNotification({
        userId: user.user_id, channel: "email", recipient: user.email,
        subject: "PRMSU Navigator Password Reset Code", message: otpTextBody,
        status: emailResult.sent ? "sent" : "failed",
        errorDetail: emailResult.sent ? null : emailResult.reason,
        context: "password_reset_otp"
      });
      if (!emailResult.sent) {
        return res.status(503).json({ ok: false, error: emailResult.reason || "Email not configured." });
      }
    }
    /* SMS DISABLED
    else {
      const smsBody = `PRMSU OTP ${otp}. Exp ${expiresMinutes}m.`;
      const smsResult = await sendPhilSms({ phone: user.phone, message: smsBody });
      await logNotification({
        userId: user.user_id, channel: "sms", recipient: user.phone,
        message: smsBody, status: smsResult.sent ? "sent" : "failed",
        errorDetail: smsResult.sent ? null : smsResult.reason,
        context: "password_reset_otp"
      });
      if (!smsResult.sent) {
        return res.status(503).json({ ok: false, error: smsResult.reason || "SMS not configured." });
      }
    }
    */

    const resetKey = getResetSessionKey(normalizedMethod, normalizedMethod === "sms" ? user.phone : user.email);
    resetSessions.set(resetKey, {
      otp,
      expiresAt,
      method: normalizedMethod,
      identifier: normalizedMethod === "sms" ? user.phone : user.email,
      verified: false,
      resetToken: null
    });

    return res.json({
      ok: true,
      email: user.email,
      identifier: normalizedMethod === "sms" ? user.phone : user.email,
      method: normalizedMethod,
      expiresInSeconds: expiresMinutes * 60,
      delivery: { method: normalizedMethod, status: "sent" }
    });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.post("/api/auth/forgot/verify", async (req, res) => {
  const { identifier, email, method, otp } = req.body || {};
  const resetIdentifier = identifier || email;
  const resetMethod = method || "email";
  if (!resetIdentifier || !otp) {
    return res.status(400).json({ ok: false, error: "Email or phone number and OTP are required." });
  }

  const entry = resetSessions.get(getResetSessionKey(resetMethod, resetIdentifier));
  if (!entry) {
    return res.status(400).json({ ok: false, error: "Reset request not found." });
  }

  if (Date.now() > entry.expiresAt) {
    resetSessions.delete(getResetSessionKey(resetMethod, resetIdentifier));
    return res.status(400).json({ ok: false, error: "OTP expired. Please request a new code." });
  }

  if (String(otp).trim() !== entry.otp) {
    return res.status(400).json({ ok: false, error: "Invalid OTP code." });
  }

  const resetToken = generateResetToken();
  resetSessions.set(getResetSessionKey(resetMethod, resetIdentifier), {
    ...entry,
    verified: true,
    resetToken
  });

  return res.json({ ok: true, resetToken });
});

app.post("/api/auth/forgot/reset", async (req, res) => {
  const { identifier, email, method, resetToken, newPassword } = req.body || {};
  const resetIdentifier = identifier || email;
  const resetMethod = method || "email";
  if (!resetIdentifier || !resetToken || !newPassword) {
    return res.status(400).json({ ok: false, error: "Missing reset details." });
  }

  const key = getResetSessionKey(resetMethod, resetIdentifier);
  const entry = resetSessions.get(key);
  if (!entry || !entry.verified || entry.resetToken !== resetToken) {
    return res.status(400).json({ ok: false, error: "Reset session invalid or expired." });
  }

  if (Date.now() > entry.expiresAt) {
    resetSessions.delete(key);
    return res.status(400).json({ ok: false, error: "Reset session expired. Please request a new code." });
  }

  try {
    const result = await pool.query(
      `UPDATE users
      SET password_hash = $1
      WHERE ${entry.method === "sms"
        ? "regexp_replace(COALESCE(phone, ''), '[^0-9]', '', 'g')"
        : "LOWER(email)"} = $2
      RETURNING full_name, email`,
      [
        await hashPassword(newPassword),
        entry.method === "sms" ? normalizeResetPhoneDigits(entry.identifier) : normalizeResetEmail(entry.identifier)
      ]
    );

    if (!result.rows.length) {
      return res.status(404).json({ ok: false, error: "User not found." });
    }

    const user = result.rows[0];
    const notifications = { email: "skipped" };

    const changedTextBody = formatPasswordChangedMessage({ name: user.full_name });
    try {
      const emailResult = await sendBrevoEmail({
        toEmail: user.email,
        toName: user.full_name,
        subject: "PRMSU Navigator Password Updated",
        textBody: changedTextBody
      });
      notifications.email = emailResult.sent ? "sent" : emailResult.reason;
      await logNotification({
        channel: "email", recipient: user.email, subject: "PRMSU Navigator Password Updated",
        message: changedTextBody, status: emailResult.sent ? "sent" : "skipped",
        context: "password_changed"
      });
    } catch (error) {
      notifications.email = `failed: ${error.message}`;
      await logNotification({
        channel: "email", recipient: user.email, subject: "PRMSU Navigator Password Updated",
        message: changedTextBody, status: "failed", errorDetail: error.message,
        context: "password_changed"
      });
    }

    resetSessions.delete(key);
    return res.json({ ok: true, notifications });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.post("/api/datasets", async (req, res) => {
  const { title, description, payload } = req.body;

  if (!title) {
    return res.status(400).json({ error: "title is required" });
  }

  try {
    const result = await pool.query(
      `INSERT INTO datasets (title, description, payload)
      VALUES ($1, $2, $3)
      RETURNING id, title, description, payload, created_at`,
      [title, description || null, payload || null]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/datasets", async (_req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, title, description, payload, created_at FROM datasets ORDER BY created_at DESC"
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── PROFILE: Get profile from DB ──
app.get("/api/auth/profile/:userId", async (req, res) => {
    const { userId } = req.params;
    try {
        const result = await pool.query(
            `SELECT user_id, full_name, email, phone, role, photo
            FROM users WHERE LOWER(user_id) = LOWER($1)`,
            [userId]
        );
        if (!result.rows.length) {
            return res.status(404).json({ ok: false, error: "User not found." });
        }
        const u = result.rows[0];
        return res.json({
            ok: true,
            user: {
                userId: u.user_id,
                name:   u.full_name,
                email:  u.email,
                phone:  u.phone  || "",
                role:   u.role,
                photo:  u.photo  || ""
            }
        });
    } catch (err) {
        return res.status(500).json({ ok: false, error: err.message });
    }
});

// ── PROFILE: Update name, email, phone ──
app.post("/api/auth/update-profile", async (req, res) => {
    const { userId, name, email, phone } = req.body || {};
    if (!userId || !name || !email) {
        return res.status(400).json({ ok: false, error: "Missing required fields." });
    }
    try {
        const result = await pool.query(
            `UPDATE users
            SET full_name = $1, email = $2, phone = $3
            WHERE LOWER(user_id) = LOWER($4)
            RETURNING user_id, full_name, email, phone, role`,
            [name.trim(), email.trim().toLowerCase(), phone?.trim() || null, userId]
        );
        if (!result.rows.length) {
            return res.status(404).json({ ok: false, error: "User not found." });
        }
        const u = result.rows[0];
        return res.json({
            ok: true,
            user: {
                userId: u.user_id,
                name:   u.full_name,
                email:  u.email,
                phone:  u.phone || ""
            }
        });
    } catch (err) {
        if (err.code === "23505") {
            return res.status(409).json({ ok: false, error: "Email already in use by another account." });
        }
        return res.status(500).json({ ok: false, error: err.message });
    }
});

// ── PROFILE: Update photo ──
app.post("/api/auth/update-photo", async (req, res) => {
    const { userId, photo } = req.body || {};
    if (!userId || !photo) {
        return res.status(400).json({ ok: false, error: "Missing userId or photo." });
    }
    if (photo.length > 3 * 1024 * 1024) {
        return res.status(413).json({ ok: false, error: "Photo too large (max ~2MB)." });
    }
    try {
        const result = await pool.query(
            `UPDATE users SET photo = $1
            WHERE LOWER(user_id) = LOWER($2)
            RETURNING user_id`,
            [photo, userId]
        );
        if (!result.rows.length) {
            return res.status(404).json({ ok: false, error: "User not found." });
        }
        return res.json({ ok: true });
    } catch (err) {
        return res.status(500).json({ ok: false, error: err.message });
    }
});

// ── PROFILE: Change password ──
app.post("/api/auth/change-password", async (req, res) => {
    const { userId, currentPassword, newPassword } = req.body || {};
    if (!userId || !currentPassword || !newPassword) {
        return res.status(400).json({ ok: false, error: "Missing required fields." });
    }
    try {
        // Verify current password (supports either hash scheme)
        const check = await pool.query(
            `SELECT user_id, password_hash FROM users WHERE LOWER(user_id) = LOWER($1)`,
            [userId]
        );
        if (!check.rows.length) {
            return res.status(401).json({ ok: false, error: "Current password is incorrect." });
        }
        const { valid } = await verifyPassword(currentPassword, check.rows[0].password_hash);
        if (!valid) {
            return res.status(401).json({ ok: false, error: "Current password is incorrect." });
        }
        // Update to new password (always bcrypt going forward)
        await pool.query(
            `UPDATE users SET password_hash = $1
            WHERE LOWER(user_id) = LOWER($2)`,
            [await hashPassword(newPassword), userId]
        );
        return res.json({ ok: true });
    } catch (err) {
        return res.status(500).json({ ok: false, error: err.message });
    }
});

app.post("/api/routes/record", async (req, res) => {
    const { userId, destination, distance, duration, isRoom, campus } = req.body || {};
    if (!userId || !destination) {
        return res.status(400).json({ ok: false, error: "Missing required fields." });
    }
    try {
        await pool.query(
            `INSERT INTO route_history
            (user_id, destination_name, distance_m, duration_s, is_room, campus, navigated_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
            [
                userId,
                String(destination),
                Math.round(Number(distance) || 0),
                Math.round(Number(duration) || 0),
                isRoom === true || isRoom === 'true',
                campus || 'iba'
            ]
        );
        return res.json({ ok: true });
    } catch (err) {
        console.error('Route record error:', err.message, err.detail);
        return res.status(500).json({ ok: false, error: err.message });
    }
});


// ── ROUTE HISTORY: Get count for a user ──
app.get("/api/routes/count/:userId", async (req, res) => {
    const { userId } = req.params;
    try {
        const result = await pool.query(
            `SELECT COUNT(*) AS total FROM route_history WHERE LOWER(user_id) = LOWER($1)`,
            [userId]
        );
        return res.json({ ok: true, total: parseInt(result.rows[0].total, 10) });
    } catch (err) {
        return res.status(500).json({ ok: false, error: err.message });
    }
});

// ══════════════════════════════════════════
// 📡 REAL-TIME ANNOUNCEMENT UPDATES (SSE)
// ══════════════════════════════════════════
// Any open tab (Main App or Admin Dashboard) can subscribe to this stream.
// Whenever an announcement is created, approved, rejected, or deleted, every
// connected client gets a tiny "something changed" ping and re-fetches its
// own announcement list — no page refresh needed on either side.
const announcementSseClients = new Set();

function broadcastAnnouncementsChanged() {
  const payload = `data: ${JSON.stringify({ type: "announcementsChanged", at: Date.now() })}\n\n`;
  for (const client of announcementSseClients) {
    client.write(payload);
  }
}

// ══════════════════════════════════════════
// ⏰ EXPIRATION SWEEP — server-authoritative real-time expiry
// ══════════════════════════════════════════
// Runs on a short interval and actively flips any approved/active
// announcement whose expires_at has passed to inactive, then broadcasts a
// change event over SSE. This is what makes expiration genuinely real-time
// across every client: the Main App AND every open Admin Dashboard tab get
// the push the moment the server notices — instead of each browser having
// to independently schedule and fire its own timer (which breaks if a tab
// is backgrounded/throttled).
const EXPIRATION_SWEEP_INTERVAL_MS = 5000; // check every 5s — lower this for tighter latency

async function sweepExpiredAnnouncements() {
  try {
    const result = await pool.query(
      `UPDATE announcements
      SET is_active = false, updated_at = NOW()
      WHERE is_active = true
        AND status = 'approved'
        AND expires_at IS NOT NULL
        AND expires_at <= NOW()
      RETURNING id`
    );
    if (result.rows.length) {
      console.log(`⏰ Expired ${result.rows.length} announcement(s): ${result.rows.map(r => r.id).join(', ')}`);
      broadcastAnnouncementsChanged();
    }
  } catch (err) {
    console.error('Expiration sweep failed:', err.message);
  }
}

setInterval(sweepExpiredAnnouncements, EXPIRATION_SWEEP_INTERVAL_MS);

// ── Visitor QR / Guest check-in ──────────────────────────────────────────
// GET  /api/checkin?entrance=MAIN  — scanned from a QR code at the entrance.
//   Returns a small HTML page that sets a visitor session via postMessage
//   and closes itself (or redirects to the app).
app.get("/api/checkin", async (req, res) => {
  const entrance = req.query.entrance || "MAIN";
  const sessionId = crypto.randomBytes(12).toString("hex");
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress;

  try {
    await pool.query(
      `INSERT INTO visitor_checkins (session_id, checkin_method, entrance, ip_address)
       VALUES ($1, 'qr', $2, $3)`,
      [sessionId, entrance, ip]
    );
  } catch (err) {
    console.error("visitor_checkins insert failed:", err.message);
  }

  const appBaseUrl = process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 3001}`;

  // Return a small redirect page that passes the visitor session to the app.
  // Using localStorage via a redirect so it works even in standalone PWA mode.
  return res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PRMSU Campus Navigator – Visitor Check-in</title>
  <style>
    body { font-family: system-ui, sans-serif; display: flex; align-items: center;
           justify-content: center; min-height: 100vh; margin: 0;
           background: #0f3a52; color: #fff; text-align: center; padding: 24px; }
    .card { background: rgba(255,255,255,0.1); border-radius: 16px;
            padding: 32px 24px; max-width: 340px; }
    h2 { margin: 0 0 8px; font-size: 22px; }
    p  { margin: 0 0 24px; opacity: .8; font-size: 14px; }
    .spinner { width: 36px; height: 36px; border: 3px solid rgba(255,255,255,0.3);
               border-top-color: #fff; border-radius: 50%;
               animation: spin .8s linear infinite; margin: 0 auto 16px; }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div class="card">
    <div class="spinner"></div>
    <h2>Welcome to PRMSU!</h2>
    <p>Starting your visitor session…</p>
  </div>
  <script>
    try {
      const session = {
        userId: null,
        name: 'Visitor',
        email: null,
        role: 'VISITOR',
        isGuest: true,
        checkinMethod: 'qr',
        entrance: ${JSON.stringify(entrance)},
        sessionId: ${JSON.stringify(sessionId)}
      };
      localStorage.setItem('campusNavigatorSession', JSON.stringify(session));
    } catch(e) {}
    window.location.replace(${JSON.stringify(appBaseUrl)});
  </script>
</body>
</html>`);
});

// POST /api/checkin/guest — called by the "Continue as Guest" button in the app.
app.post("/api/checkin/guest", async (req, res) => {
  const sessionId = crypto.randomBytes(12).toString("hex");
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress;

  try {
    await pool.query(
      `INSERT INTO visitor_checkins (session_id, checkin_method, entrance, ip_address)
       VALUES ($1, 'guest', NULL, $2)`,
      [sessionId, ip]
    );
  } catch (err) {
    console.error("visitor_checkins insert failed:", err.message);
  }

  return res.json({ ok: true, sessionId });
});

app.get("/api/announcements/stream", (req, res) => {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no" // don't let a reverse proxy buffer this stream
  });
  res.write(`data: ${JSON.stringify({ type: "connected" })}\n\n`);
  announcementSseClients.add(res);

  // Keep the connection alive through proxies/load balancers that otherwise
  // time out an idle HTTP connection after ~30-60s.
  const heartbeat = setInterval(() => {
    res.write(`: heartbeat\n\n`);
  }, 25000);

  req.on("close", () => {
    clearInterval(heartbeat);
    announcementSseClients.delete(res);
  });
});

// ══════════════════════════════════════════
// 🟢 ACTIVE USERS — real-time "who's online" presence (SSE)
// ══════════════════════════════════════════
// Same pattern as the announcements stream above: every open tab (Main App
// or Admin Dashboard) opens one long-lived connection while the user is
// logged in. We key presence by userId (not by connection) so a user with
// two tabs open still only counts once. The moment a connection opens or
// closes, every connected client gets the fresh count pushed to it — no
// polling needed.
const activeUserConnections = new Map(); // userId -> { role, conns: Set<res> }

function getActiveUsersSnapshot() {
  const byRole = {};
  for (const { role } of activeUserConnections.values()) {
    byRole[role] = (byRole[role] || 0) + 1;
  }
  return { total: activeUserConnections.size, byRole };
}

function broadcastActiveUserCount() {
  const snapshot = getActiveUsersSnapshot();
  const payload = `data: ${JSON.stringify({ type: "activeUsers", ...snapshot })}\n\n`;
  for (const { conns } of activeUserConnections.values()) {
    for (const client of conns) client.write(payload);
  }
}

app.get("/api/active-users/stream", (req, res) => {
  // Anonymous/guest visitors (no session yet) still count as "using the
  // system" — give each one a throwaway id scoped to this connection only,
  // so they don't collide with a real userId and don't persist after the
  // tab closes.
  const userId = req.query.userId ? String(req.query.userId) : `guest-${crypto.randomUUID()}`;
  const role = Permissions.normalizeRole(req.query.role); // fails-closed to VISITOR if missing/unknown

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no"
  });
  res.write(`data: ${JSON.stringify({ type: "connected" })}\n\n`);

  if (!activeUserConnections.has(userId)) {
    activeUserConnections.set(userId, { role, conns: new Set() });
  }
  activeUserConnections.get(userId).conns.add(res);
  broadcastActiveUserCount();

  const heartbeat = setInterval(() => {
    res.write(`: heartbeat\n\n`);
  }, 25000);

  req.on("close", () => {
    clearInterval(heartbeat);
    const entry = activeUserConnections.get(userId);
    if (entry) {
      entry.conns.delete(res);
      if (entry.conns.size === 0) activeUserConnections.delete(userId);
    }
    broadcastActiveUserCount();
  });
});

// One-shot fetch for pages that just need the numbers once on load (e.g.
// Admin Dashboard's stat card on initial render), without opening a stream.
app.get("/api/active-users/count", (_req, res) => {
  res.json({ ok: true, ...getActiveUsersSnapshot() });
});

// ══════════════════════════════════════════
// 🗺️ REAL-TIME MAP DATA (buildings/rooms) UPDATES (SSE)
// ══════════════════════════════════════════
// Same pattern as the announcements stream above. Whenever a building or
// room is added, edited, or deleted from the Admin Dashboard, every
// connected client (Main App tabs AND other Admin Dashboard tabs) gets a
// tiny "something changed" ping and re-syncs from the DB — so a deleted
// room disappears from markers, the room list, and Show Room(s) instantly,
// without a page refresh and without stale data lingering in memory.
const mapDataSseClients = new Set();

function broadcastMapDataChanged() {
  const payload = `data: ${JSON.stringify({ type: "mapDataChanged", at: Date.now() })}\n\n`;
  for (const client of mapDataSseClients) {
    client.write(payload);
  }
}

app.get("/api/map-data/stream", (req, res) => {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no"
  });
  res.write(`data: ${JSON.stringify({ type: "connected" })}\n\n`);
  mapDataSseClients.add(res);

  const heartbeat = setInterval(() => {
    res.write(`: heartbeat\n\n`);
  }, 25000);

  req.on("close", () => {
    clearInterval(heartbeat);
    mapDataSseClients.delete(res);
  });
});

// ══════════════════════════════════════════
// 🔀 CONSOLIDATED REAL-TIME STREAM (announcements + active users + map data)
// ══════════════════════════════════════════
// Every open tab (Main App or Admin Dashboard) previously opened THREE
// separate persistent SSE connections (announcements, active-users,
// map-data). Browsers cap concurrent connections to the same origin at 6
// for HTTP/1.1 — so with the Admin Dashboard open in one tab and the Main
// App open in another (exactly how someone would test "does the Main App
// update when I delete something in Admin"), that's 6 permanently-open
// connections, saturating the pool. Whichever stream happened to be
// opened last (map-data, since it connects after the other two) would
// silently queue behind the others and never actually deliver events —
// which is why room-deletion sync could appear to work sometimes (single
// tab) and not others (Admin + Main App open together).
//
// Fix: multiplex all three event types over ONE connection per tab. This
// endpoint registers a single response object across all three existing
// broadcast mechanisms above, so broadcastAnnouncementsChanged(),
// broadcastActiveUserCount(), and broadcastMapDataChanged() all reach it
// without any change to how those functions work.
app.get("/api/realtime/stream", (req, res) => {
  const userId = req.query.userId ? String(req.query.userId) : `guest-${crypto.randomUUID()}`;
  const role = Permissions.normalizeRole(req.query.role);

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no"
  });
  res.write(`data: ${JSON.stringify({ type: "connected" })}\n\n`);

  announcementSseClients.add(res);
  mapDataSseClients.add(res);

  if (!activeUserConnections.has(userId)) {
    activeUserConnections.set(userId, { role, conns: new Set() });
  }
  activeUserConnections.get(userId).conns.add(res);
  broadcastActiveUserCount();

  const heartbeat = setInterval(() => {
    res.write(`: heartbeat\n\n`);
  }, 25000);

  req.on("close", () => {
    clearInterval(heartbeat);
    announcementSseClients.delete(res);
    mapDataSseClients.delete(res);
    const entry = activeUserConnections.get(userId);
    if (entry) {
      entry.conns.delete(res);
      if (entry.conns.size === 0) activeUserConnections.delete(userId);
    }
    broadcastActiveUserCount();
  });
});

// ══════════════════════════════════════════
// 📢 ANNOUNCEMENTS
// ══════════════════════════════════════════

app.get("/api/announcements", async (req, res) => {
  const activeOnly = req.query.active === "true";
  try {
    const result = await pool.query(
      activeOnly
        ? `SELECT * FROM announcements
          WHERE is_active = true AND status = 'approved'
            AND (expires_at IS NULL OR expires_at > NOW())
          ORDER BY created_at DESC`
        : `SELECT * FROM announcements WHERE status = 'approved' ORDER BY created_at DESC`
    );
    return res.json({ ok: true, announcements: result.rows });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/announcements", requireAdmin, async (req, res) => {
  const { title, message, type, adminUserId } = req.body || {};
  if (!title || !message) {
    return res.status(400).json({ ok: false, error: "Title and message are required." });
  }
  try {
    const result = await pool.query(
      `INSERT INTO announcements (title, message, type, created_by)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [title.trim(), message.trim(), type || "info", adminUserId]
    );
    await logAudit({
      adminUserId, action: "create", entityType: "announcement",
      entityId: result.rows[0].id, details: result.rows[0]
    });
    broadcastAnnouncementsChanged();
    return res.status(201).json({ ok: true, announcement: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.put("/api/announcements/:id", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { title, message, type, isActive } = req.body || {};
  try {
    const result = await pool.query(
      `UPDATE announcements
      SET title = COALESCE($1, title),
          message = COALESCE($2, message),
          type = COALESCE($3, type),
          is_active = COALESCE($4, is_active),
          updated_at = NOW()
      WHERE id = $5
       RETURNING *`,
      [title, message, type, isActive, id]
    );
    if (!result.rows.length) return res.status(404).json({ ok: false, error: "Announcement not found." });
    return res.json({ ok: true, announcement: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.delete("/api/announcements/:id", requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(`DELETE FROM announcements WHERE id = $1 RETURNING id`, [id]);
    if (!result.rows.length) return res.status(404).json({ ok: false, error: "Announcement not found." });
    broadcastAnnouncementsChanged();
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// ══════════════════════════════════════════
// 📅 EVENTS
// ══════════════════════════════════════════

app.get("/api/events", async (_req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM events ORDER BY event_date ASC, start_time ASC`);
    return res.json({ ok: true, events: result.rows });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/events", requireAdmin, async (req, res) => {
  const { title, description, location, eventDate, startTime, endTime, adminUserId } = req.body || {};
  if (!title || !eventDate) {
    return res.status(400).json({ ok: false, error: "Title and event date are required." });
  }
  try {
    const result = await pool.query(
      `INSERT INTO events (title, description, location, event_date, start_time, end_time, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [title.trim(), description || null, location || null, eventDate, startTime || null, endTime || null, adminUserId]
    );
    return res.status(201).json({ ok: true, event: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.put("/api/events/:id", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { title, description, location, eventDate, startTime, endTime } = req.body || {};
  try {
    const result = await pool.query(
      `UPDATE events
      SET title = COALESCE($1, title),
          description = COALESCE($2, description),
          location = COALESCE($3, location),
          event_date = COALESCE($4, event_date),
          start_time = COALESCE($5, start_time),
          end_time = COALESCE($6, end_time),
          updated_at = NOW()
      WHERE id = $7
       RETURNING *`,
      [title, description, location, eventDate, startTime, endTime, id]
    );
    if (!result.rows.length) return res.status(404).json({ ok: false, error: "Event not found." });
    return res.json({ ok: true, event: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.delete("/api/events/:id", requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(`DELETE FROM events WHERE id = $1 RETURNING id`, [id]);
    if (!result.rows.length) return res.status(404).json({ ok: false, error: "Event not found." });
    broadcastAnnouncementsChanged();
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// ══════════════════════════════════════════
// 🔧 ADMIN ROUTES
// ══════════════════════════════════════════

app.get("/api/admin/users", requireAdmin, async (_req, res) => {
  try {
    const result = await pool.query(
      `SELECT user_id, full_name, email, role, created_at FROM users ORDER BY created_at DESC`
    );
    return res.json({ ok: true, users: result.rows });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// ── Pending Student/Employee ID verification ────────────────────────────
app.get("/api/admin/users/pending", requireAdmin, async (_req, res) => {
  try {
    const result = await pool.query(
      `SELECT user_id, full_name, email, role, created_at, id_document
       FROM users
       WHERE verification_status = 'pending'
       ORDER BY created_at ASC`
    );
    return res.json({ ok: true, users: result.rows });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.put("/api/admin/users/:userId/approve", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE users SET verification_status = 'approved'
       WHERE LOWER(user_id) = LOWER($1) RETURNING user_id, full_name, email, role, verification_status`,
      [req.params.userId]
    );
    if (!result.rows.length) return res.status(404).json({ ok: false, error: "User not found." });
    await logAudit({
      adminUserId: req.body?.adminUserId || req.query?.adminUserId,
      action: "user_verification_approve",
      entityType: "user",
      entityId: req.params.userId,
      details: {}
    });
    return res.json({ ok: true, user: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.put("/api/admin/users/:userId/reject", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE users SET verification_status = 'rejected'
       WHERE LOWER(user_id) = LOWER($1) RETURNING user_id, full_name, email, role, verification_status`,
      [req.params.userId]
    );
    if (!result.rows.length) return res.status(404).json({ ok: false, error: "User not found." });
    await logAudit({
      adminUserId: req.body?.adminUserId || req.query?.adminUserId,
      action: "user_verification_reject",
      entityType: "user",
      entityId: req.params.userId,
      details: {}
    });
    return res.json({ ok: true, user: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.put("/api/admin/users/:userId/role", requireAdmin, async (req, res) => {
  const { role } = req.body || {};
  const normalizedRole = String(role || "").toUpperCase();
  if (!["STUDENT", "EMPLOYEE", "VISITOR", "ADMIN"].includes(normalizedRole)) {
    return res.status(400).json({ ok: false, error: "Invalid role." });
  }
  try {
    const result = await pool.query(
      `UPDATE users SET role = $1 WHERE LOWER(user_id) = LOWER($2) RETURNING user_id, full_name, email, role`,
      [normalizedRole, req.params.userId]
    );
    if (!result.rows.length) return res.status(404).json({ ok: false, error: "User not found." });
    await logAudit({
      adminUserId: req.body?.adminUserId || req.query?.adminUserId,
      action: "role_change",
      entityType: "user",
      entityId: req.params.userId,
      details: { newRole: normalizedRole }
    });
    return res.json({ ok: true, user: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/admin/stats/users", requireAdmin, async (_req, res) => {
  try {
    const result = await pool.query(`SELECT COUNT(*) AS total FROM users`);
    return res.json({ ok: true, total: parseInt(result.rows[0].total, 10) });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/admin/stats/routes", requireAdmin, async (_req, res) => {
  try {
    const result = await pool.query(`SELECT COUNT(*) AS total FROM route_history`);
    return res.json({ ok: true, total: parseInt(result.rows[0].total, 10) });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// ── ANALYTICS: most-searched buildings, busiest routes, peak usage times ──
// All three pull from route_history (populated by /api/routes/record on
// every completed navigation), so this reflects real usage rather than
// static campus-data.js counts.
app.get("/api/admin/analytics", requireAdmin, async (req, res) => {
  try {
    // Optional windowing — defaults to "all time" if not provided, so the
    // dashboard has something to show immediately with no query params.
    // `range` is either "today" (calendar-day boundary in Asia/Manila —
    // NOT a rolling 24h window) or a plain number of days (e.g. "7").
    const range = String(req.query.range ?? req.query.days ?? '').trim();
    let sinceClause = '';

    if (range === 'today') {
      // date_trunc('day', NOW() AT TIME ZONE 'Asia/Manila') gives midnight
      // as a naive timestamp in Manila wall-clock time; re-applying
      // AT TIME ZONE 'Asia/Manila' converts that naive value back into the
      // correct absolute UTC instant for comparison against the
      // timestamptz column. This is what makes "Today" mean "since
      // midnight Manila time", not "since midnight UTC" or "last 24h".
      sinceClause = `WHERE navigated_at >= (date_trunc('day', NOW() AT TIME ZONE 'Asia/Manila') AT TIME ZONE 'Asia/Manila')`;
    } else {
      const days = parseInt(range, 10);
      if (Number.isFinite(days) && days > 0) {
        sinceClause = `WHERE navigated_at >= NOW() - INTERVAL '${days} days'`;
      }
    }

    // Most-searched buildings/rooms — top destination_name by hit count.
    const topDestinationsPromise = pool.query(
      `SELECT destination_name, campus, is_room, COUNT(*)::int AS hits
       FROM route_history
       ${sinceClause}
       GROUP BY destination_name, campus, is_room
       ORDER BY hits DESC
       LIMIT 10`
    );

    // Busiest routes — same grouping but keyed by campus, so admins can see
    // which campus is generating the most navigation traffic overall.
    const busiestRoutesPromise = pool.query(
      `SELECT campus, COUNT(*)::int AS hits,
              ROUND(AVG(distance_m))::int AS avg_distance_m,
              ROUND(AVG(duration_s))::int AS avg_duration_s
       FROM route_history
       ${sinceClause}
       GROUP BY campus
       ORDER BY hits DESC`
    );

    // Peak usage times — hour-of-day histogram, restricted to campus
    // operating hours (5:00 AM–5:00 PM inclusive, i.e. hours 5 through 17).
    // Left-joined against generate_series so hours with zero activity still
    // show up as 0 instead of being omitted; navigations outside this
    // window (evenings/nights) are simply excluded from the series and
    // never counted anywhere in the result.
    const peakHoursPromise = pool.query(
      `SELECT h.hour, COUNT(rh.*)::int AS hits
       FROM generate_series(5, 17) AS h(hour)
       LEFT JOIN route_history rh
         ON EXTRACT(HOUR FROM rh.navigated_at AT TIME ZONE 'Asia/Manila') = h.hour
         ${sinceClause ? sinceClause.replace('WHERE', 'AND') : ''}
       GROUP BY h.hour
       ORDER BY h.hour`
    );

    const [topDestinations, busiestRoutes, peakHours] = await Promise.all([
      topDestinationsPromise,
      busiestRoutesPromise,
      peakHoursPromise
    ]);

    return res.json({
      ok: true,
      topDestinations: topDestinations.rows,
      busiestRoutes: busiestRoutes.rows,
      peakHours: peakHours.rows
    });
  } catch (err) {
    console.error('Analytics error:', err.message, err.detail);
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/admin/announcements", requireAdmin, async (_req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM announcements ORDER BY created_at DESC`);
    return res.json({ ok: true, announcements: result.rows });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/admin/announcements", requireAdmin, async (req, res) => {
  const { message, type, expires_at, adminUserId } = req.body || {};
  if (!message) return res.status(400).json({ ok: false, error: "Message is required." });
  try {
    const result = await pool.query(
      `INSERT INTO announcements (title, message, type, expires_at, created_by, is_active)
      VALUES ($1, $2, $3, $4, $5, true) RETURNING *`,
      [message.trim(), message.trim(), type || "info", expires_at || null, adminUserId || null]
    );
    broadcastAnnouncementsChanged();
    return res.status(201).json({ ok: true, announcement: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.delete("/api/admin/announcements/:id", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`DELETE FROM announcements WHERE id = $1 RETURNING id`, [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ ok: false, error: "Not found." });
    broadcastAnnouncementsChanged(); 
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.put("/api/admin/announcements/:id/approve", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE announcements SET status = 'approved', is_active = true, updated_at = NOW()
       WHERE id = $1 RETURNING *`,
      [req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ ok: false, error: "Not found." });
    broadcastAnnouncementsChanged();
    return res.json({ ok: true, announcement: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.put("/api/admin/announcements/:id/reject", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE announcements SET status = 'rejected', is_active = false, updated_at = NOW()
       WHERE id = $1 RETURNING *`,
      [req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ ok: false, error: "Not found." });
    broadcastAnnouncementsChanged();
    return res.json({ ok: true, announcement: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// ── Employee submits an announcement for admin review ──
app.post("/api/announcements/submit", async (req, res) => {
  const { userId, message, type, expires_at } = req.body || {};
  if (!userId || !message) {
    return res.status(400).json({ ok: false, error: "userId and message are required." });
  }
  try {
    const role = await getCallerRole({ body: { userId } });
    const config = Permissions.getRoleConfig(role);
    if (!config.features?.submitAnnouncements) {
      return res.status(403).json({ ok: false, error: "Your account type cannot submit announcements." });
    }
    const result = await pool.query(
      `INSERT INTO announcements (title, message, type, expires_at, created_by, is_active, status)
       VALUES ($1, $2, $3, $4, $5, false, 'pending') RETURNING *`,
      [message.trim(), message.trim(), type || "info", expires_at || null, userId]
    );
    broadcastAnnouncementsChanged();
    return res.status(201).json({ ok: true, announcement: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/admin/events", requireAdmin, async (_req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM events ORDER BY start_at ASC NULLS LAST`);
    return res.json({ ok: true, events: result.rows });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/admin/events", requireAdmin, async (req, res) => {
  const { title, location, start_at, end_at, description } = req.body || {};
  if (!title || !start_at) return res.status(400).json({ ok: false, error: "Title and start time are required." });
  try {
    const result = await pool.query(
      `INSERT INTO events (title, description, location, start_at, end_at, created_by)
       VALUES ($1, $2, $3, $4, $5, 'admin') RETURNING *`,
      [title.trim(), description || null, location || null, start_at, end_at || null]
    );
    return res.status(201).json({ ok: true, event: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.delete("/api/admin/events/:id", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`DELETE FROM events WHERE id = $1 RETURNING id`, [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ ok: false, error: "Not found." });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// ── GraphHopper walking-directions proxy — keeps GRAPHHOPPER_API_KEY
// server-side only. Converts GraphHopper's response shape into the same
// ORS-style GeoJSON shape script.js's fetchORSRoute() already expects,
// so the client code needs zero changes.
const GRAPHHOPPER_API_KEY = process.env.GRAPHHOPPER_API_KEY;

// GraphHopper "sign" codes → the numeric codes mapORSManeuverToType()
// in script.js already understands (0=turn-left,1=turn-right,2=sharp-left,
// 3=sharp-right,4=slight-left,5=slight-right,6=straight,9=uturn,10=arrive,11=depart)
function mapGHSignToORSType(sign) {
  const signMap = {
    "-3": 2,  // sharp left
    "-2": 0,  // left
    "-1": 4,  // slight left
    "0": 6,   // continue/straight
    "1": 5,   // slight right
    "2": 1,   // right
    "3": 3,   // sharp right
    "4": 10,  // finish/arrive
    "5": 10,  // via reached
    "6": 6,   // roundabout (approx)
    "-8": 9,  // left u-turn
    "8": 9    // right u-turn
  };
  return signMap[String(sign)] ?? 6;
}

app.post("/api/route", async (req, res) => {
  const { coordinates, profile } = req.body || {};
  if (!Array.isArray(coordinates) || coordinates.length < 2) {
    return res.status(400).json({ ok: false, error: "coordinates ([[lng,lat],[lng,lat],...]) with at least 2 points is required." });
  }
  if (!GRAPHHOPPER_API_KEY) {
    return res.status(500).json({ ok: false, error: "GRAPHHOPPER_API_KEY is not configured on the server." });
  }

  try {
    const GH_PROFILE_MAP = { "driving-car": "car", "cycling-regular": "bike", "foot": "foot" };
    const ghProfile = GH_PROFILE_MAP[profile] || "foot";
    const pointParams = coordinates.map(([lng, lat]) => `point=${lat},${lng}`).join("&");
    const url = `https://graphhopper.com/api/1/route?${pointParams}&vehicle=${ghProfile}&weighting=fastest&key=${GRAPHHOPPER_API_KEY}&points_encoded=false&instructions=true`;

    const response = await fetch(url);
    const data = await response.json();

    if (!response.ok || !data.paths?.length) {
      const message = data?.message || "GraphHopper request failed.";
      return res.status(response.status || 500).json({ ok: false, error: message });
    }

    const path = data.paths[0];

    // Reshape into the same ORS GeoJSON structure script.js already parses.
    const route = {
      features: [{
        geometry: { coordinates: path.points.coordinates },
        properties: {
          segments: [{
            steps: (path.instructions || []).map(step => ({
              type: mapGHSignToORSType(step.sign),
              name: step.street_name || "",
              distance: step.distance
            }))
          }],
          summary: {
            distance: path.distance,
            duration: path.time / 1000 // GraphHopper gives ms, ORS gives seconds
          }
        }
      }]
    };

    return res.json({ ok: true, route });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// GET all rooms
app.get("/api/admin/checkins", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, session_id, checkin_method, entrance, checked_in_at, ip_address
       FROM visitor_checkins
       ORDER BY checked_in_at DESC
       LIMIT 200`
    );
    return res.json({ ok: true, checkins: result.rows });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/api/rooms', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT r.*, b.type AS building_type
      FROM rooms r LEFT JOIN buildings b ON b.short_name = r.building
      ORDER BY r.building, r.name`
    );
    const role = await getCallerRole(req);
    const rooms = result.rows.filter(r =>
      Permissions.assertLocationTypeAllowed(role, r.building_type || 'department')
    );
    res.json({ ok: true, rooms });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// POST add a room
app.post('/api/admin/rooms', requireAdmin, async (req, res) => {
  const { building, name, floor, instructor, lat, lng, icon_offset_x, icon_offset_y } = req.body;
  if (!building || !name) return res.status(400).json({ ok: false, error: 'building and name required' });
  try {
    const result = await pool.query(
      `INSERT INTO rooms (building, name, floor, instructor, lat, lng, icon_offset_x, icon_offset_y)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [building, name, floor || '—', instructor || null,
      lat || null, lng || null,
      icon_offset_x || 0, icon_offset_y || 0]
    );
    broadcastMapDataChanged(); // ✅ ADD — push instant "room added" to every open tab
    res.json({ ok: true, room: result.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// PUT edit a room
app.put('/api/admin/rooms/:id', requireAdmin, async (req, res) => {
  const { building, name, floor, instructor, lat, lng, icon_offset_x, icon_offset_y } = req.body;
  try {
    const result = await pool.query(
      `UPDATE rooms SET building=$1, name=$2, floor=$3, instructor=$4,
      lat=$5, lng=$6, icon_offset_x=$7, icon_offset_y=$8
       WHERE id=$9 RETURNING *`,
      [building, name, floor || '—', instructor || null,
      lat || null, lng || null,
      icon_offset_x || 0, icon_offset_y || 0,
      req.params.id]
    );
    broadcastMapDataChanged(); // ✅ ADD — push instant "room updated" to every open tab
    res.json({ ok: true, room: result.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// DELETE a room
app.delete('/api/admin/rooms/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM rooms WHERE id=$1', [req.params.id]);
    // ✅ ADD — instantly tells every open Main App / Admin Dashboard tab to
    // re-sync from the DB, so the deleted room's marker, list entry, and
    // Show Room(s) entry disappear immediately — no refresh, no stale data.
    broadcastMapDataChanged();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Get all buildings
app.get('/api/buildings', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM buildings ORDER BY name');
    const role = await getCallerRole(req);
    const buildings = result.rows.filter(b =>
      Permissions.assertLocationTypeAllowed(role, b.type)
    );
    res.json({ ok: true, buildings });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Get all trees (decorative 3D foliage — no role filtering, same as static
// footprints: they're not a navigable "location" gated by Permissions).
app.get('/api/trees', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM trees ORDER BY id');
    res.json({ ok: true, trees: result.rows });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// POST add a tree
app.post('/api/admin/trees', requireAdmin, async (req, res) => {
  const { lat, lng, building_id, trunk_height, canopy_height, canopy_radius } = req.body;
  if (lat == null || lng == null) return res.status(400).json({ ok: false, error: 'lat and lng required' });
  try {
    const result = await pool.query(
      `INSERT INTO trees (lat, lng, building_id, trunk_height, canopy_height, canopy_radius)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [
        lat, lng, building_id || null,
        trunk_height != null ? trunk_height : 2,
        canopy_height != null ? canopy_height : 5,
        canopy_radius != null ? canopy_radius : 1.5
      ]
    );
    broadcastMapDataChanged();
    res.json({ ok: true, tree: result.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// PUT edit a tree
app.put('/api/admin/trees/:id', requireAdmin, async (req, res) => {
  const { lat, lng, building_id, trunk_height, canopy_height, canopy_radius } = req.body;
  if (lat == null || lng == null) return res.status(400).json({ ok: false, error: 'lat and lng required' });
  try {
    const result = await pool.query(
      `UPDATE trees SET lat=$1, lng=$2, building_id=$3, trunk_height=$4, canopy_height=$5, canopy_radius=$6
       WHERE id=$7 RETURNING *`,
      [
        lat, lng, building_id || null,
        trunk_height != null ? trunk_height : 2,
        canopy_height != null ? canopy_height : 5,
        canopy_radius != null ? canopy_radius : 1.5,
        req.params.id
      ]
    );
    broadcastMapDataChanged();
    res.json({ ok: true, tree: result.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// DELETE a tree
app.delete('/api/admin/trees/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM trees WHERE id=$1', [req.params.id]);
    broadcastMapDataChanged();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// POST add a building
app.post('/api/admin/buildings', requireAdmin, async (req, res) => {
  const { name, short_name, type, lat, lng, footprint, footprint_height, description } = req.body;
  if (!name || !short_name) return res.status(400).json({ ok: false, error: 'name and short_name required' });
  try {
    const result = await pool.query(
      `INSERT INTO buildings
        (name, short_name, type, lat, lng, footprint, footprint_color, footprint_opacity, footprint_height, description)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [
        name, short_name, type || 'department', lat || null, lng || null,
        footprint && footprint.length >= 3 ? JSON.stringify(footprint) : null,
        '#d1cdc7',
        1,
        footprint_height != null ? footprint_height : 4,
        description ? description.trim() : null
      ]
    );
    broadcastMapDataChanged(); // ✅ ADD — push instant "building added" to every open tab
    res.json({ ok: true, building: result.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// PUT edit a building
app.put('/api/admin/buildings/:id', requireAdmin, async (req, res) => {
  const { name, short_name, type, lat, lng, footprint, footprint_height, description } = req.body;
  try {
    const result = await pool.query(
      `UPDATE buildings
      SET name=$1, short_name=$2, type=$3, lat=$4, lng=$5,
          footprint=$6, footprint_color=$7, footprint_opacity=$8, footprint_height=$9, description=$10
       WHERE id=$11 RETURNING *`,
      [
        name, short_name, type || 'department', lat || null, lng || null,
        footprint && footprint.length >= 3 ? JSON.stringify(footprint) : null,
        '#d1cdc7',
        1,
        footprint_height != null ? footprint_height : 4,
        description ? description.trim() : null,
        req.params.id
      ]
    );
    broadcastMapDataChanged(); // ✅ ADD — push instant "building updated" to every open tab
    res.json({ ok: true, building: result.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// DELETE a building
app.delete('/api/admin/buildings/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM buildings WHERE id=$1', [req.params.id]);
    // ✅ ADD — same instant-sync push as room deletion above. Deleting a
    // building also cascades away its rooms visually on every open tab.
    broadcastMapDataChanged();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.listen(port, () => {
  console.log(`Supabase API running on http://localhost:${port}`);
});