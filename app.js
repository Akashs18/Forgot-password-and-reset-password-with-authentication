import express from "express";
import path from "path";
import { Pool } from "pg";
import nodemailer from "nodemailer";
import crypto from "crypto";
import bcrypt from "bcrypt";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import "dotenv/config";
import multer from "multer";

const storage = multer.diskStorage({
  destination: "public/uploads",
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  }
});

const upload = multer({ storage });



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
  port: 5432,
  ssl: {
    rejectUnauthorized: false
  }
});

// -------------------- SESSION STORE --------------------
const PgSession = connectPgSimple(session);

app.use(
  session({
    store: new PgSession({
      pool,
      tableName: "session",
      createTableIfMissing: true, // automatically create table if not exists
    }),
    secret: "supersecret123456",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false,
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24
    }
  })
);
 
// -------------------- EMAIL --------------------
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",  // Use explicit host
  port: 587,               // SSL port
  secure: false,            // true = SSL
  auth: {
    user: GMAIL_USER,
    pass: GMAIL_PASS      // Use Gmail App Password
  },
  tls: {
    rejectUnauthorized: false
  }
});

// -------------------- AUTH MIDDLEWARE --------------------
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/");
  }
  next();
}

//-------------------middleware----------------
app.use((req, res, next) => {
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, private"
  );
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
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

    // ✅ CREATE SESSION
    req.session.userId = user.id;
    req.session.email = user.email;

    res.redirect("/dashboard");

  } catch (err) {
    console.error(err);
    res.send("Server error");
  }
});

// DASHBOARD
app.get("/dashboard", requireAuth, (req, res) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");

  res.render("dashboard", { email: req.session.email });
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
// LOGOUT
app.post("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) return res.send("Logout failed");

    res.clearCookie("connect.sid");
    res.redirect(303, "/"); // forces browser to forget history entry
  });
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

//-----------------------local-purchase-----------------
app.post("/local-purchase", upload.single("bill"), async (req, res) => {
  try {
    const { item, vendor, quantity, price, date } = req.body;
    const billFile = req.file ? `/uploads/${req.file.filename}` : null;

    await pool.query(
      `INSERT INTO local_purchases (item, vendor, quantity, price, purchase_date, bill_file)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [item, vendor, quantity, price, date, billFile]
    );

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});


app.get("/local-purchase", async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM local_purchases ORDER BY id DESC"
  );
  res.json(result.rows);
});
 //--------delete-----------
 app.delete("/local-purchase/:id", async (req, res) => {
  await pool.query("DELETE FROM local_purchases WHERE id=$1", [req.params.id]);
  res.json({ success: true });
});


//--------------update------------
app.put("/local-purchase/:id", async (req, res) => {
  const { item, vendor, quantity, price, date } = req.body;

  await pool.query(
    `UPDATE local_purchases
     SET item=$1, vendor=$2, quantity=$3, price=$4, purchase_date=$5
     WHERE id=$6`,
    [item, vendor, quantity, price, date, req.params.id]
  );

  res.json({ success: true });
});







// -------------------- START SERVER --------------------
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
