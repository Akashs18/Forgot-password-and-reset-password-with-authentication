import express from "express";
import path from "path";
import { Pool } from "pg";
import nodemailer from "nodemailer";
import crypto from "crypto";
import bcrypt from "bcrypt";

// -------------------- CONFIG --------------------
const app = express();
const PORT = 3000;
const GMAIL_USER = "la4400512@gmail.com"; // replace with your Gmail
const GMAIL_PASS = "zsfs dvwg peso xokp";   // replace with Gmail App Password

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(path.resolve(), "public")));

// -------------------- DATABASE --------------------
const pool = new Pool({
  user: "firstdemo_examle_user",
  host: "dpg-d50evbfgi27c73aje1pg-a.oregon-postgres.render.com",
  database: "firstdemo_examle",
  password: "6LBDu09slQHqq3r0GcwbY1nPera4H5Kk",
  port: 5432
});

// -------------------- EMAIL --------------------
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: GMAIL_USER,
    pass: GMAIL_PASS
  }
});

// -------------------- ROUTES --------------------

// HOME / LOGIN
app.get("/", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE LOWER(email)=LOWER($1)",
      [email]
    );

    if (result.rowCount === 0) return res.render("login", { error: "User not found" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) return res.render("login", { error: "Incorrect password" });

    res.redirect("/dashboard");

  } catch (err) {
    console.error(err);
    res.send("Server error");
  }
});

// DASHBOARD
app.get("/dashboard", (req, res) => {
  res.render("dashboard");
});

// SIGNUP
app.get("/signup", (req, res) => {
  res.render("signup", { error: null });
});

app.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const passwordRegex = /^(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{6,}$/;
    if (!passwordRegex.test(password)) {
      return res.render("signup", {
        error: "Password must be at least 6 characters, include a number and special character"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (username, email, password) VALUES ($1, $2, $3)",
      [username, email, hashedPassword]
    );

    res.redirect("/");

  } catch (err) {
    console.error(err);
    res.render("signup", { error: "Database error or user already exists" });
  }
});

// -------------------- FORGOT PASSWORD --------------------
app.get("/forgot", (req, res) => {
  res.render("forgot", { error: null, message: null });
});

app.post("/forgot", async (req, res) => {
  try {
    const email = req.body.email?.trim();

    const result = await pool.query(
      "SELECT id FROM users WHERE LOWER(email) = LOWER($1)",
      [email]
    );

    if (result.rowCount === 0) {
      return res.render("forgot", { error: "Email not found", message: null });
    }

    const token = crypto.randomBytes(20).toString("hex");
    const expire = Date.now() + 10 * 60 * 1000; // 10 minutes

    await pool.query(
      "UPDATE users SET reset_token=$1, token_expire=$2 WHERE LOWER(email)=LOWER($3)",
      [token, expire, email]
    );

    const resetLink = `http://localhost:${PORT}/reset/${token}`;

    await transporter.sendMail({
      to: email,
      subject: "Password Reset",
      html: `<h2>Password Reset</h2>
             <p>Click below to reset password:</p>
             <a href="${resetLink}">${resetLink}</a>
             <p>Link expires in 10 minutes</p>`
    });

    res.render("forgot", { error: null, message: "Reset link sent to email" });

  } catch (err) {
    console.error(err);
    res.send("Server error");
  }
});

// -------------------- RESET PASSWORD --------------------
app.get("/reset/:token", async (req, res) => {
  const { token } = req.params;

  const result = await pool.query(
    "SELECT id FROM users WHERE reset_token=$1 AND token_expire>$2",
    [token, Date.now()]
  );

  if (result.rowCount === 0) return res.send("Invalid or expired token");

  res.render("reset", { token });
});

app.post("/reset/:token", async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  const result = await pool.query(
    "SELECT id FROM users WHERE reset_token=$1 AND token_expire>$2",
    [token, Date.now()]
  );

  if (result.rowCount === 0) return res.send("Invalid or expired token");

  const hashedPassword = await bcrypt.hash(password, 10);

  await pool.query(
    `UPDATE users
     SET password=$1, reset_token=NULL, token_expire=NULL
     WHERE reset_token=$2`,
    [hashedPassword, token]
  );

  res.send("Password updated successfully. You can now login.");
});

// -------------------- START SERVER --------------------
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
