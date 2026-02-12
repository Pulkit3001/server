require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const requestLogger = require("./middleware/logger");
const authMiddleware = require("./middleware/auth");

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory storage
const loginSessions = {};
const otpStore = {};

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(requestLogger);

app.get("/", (req, res) => {
  res.json({
    challenge: "Complete the Authentication Flow",
    instruction:
      "Complete the authentication flow and obtain a valid access token.",
  });
});

/* ============================
   TASK 1: FIX LOGIN
============================ */
app.post("/auth/login", (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    const loginSessionId = Math.random().toString(36).substring(2, 15);
    const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Always string

    loginSessions[loginSessionId] = {
      email,
      createdAt: Date.now(),
      expiresAt: Date.now() + 2 * 60 * 1000, // 2 minutes
    };

    otpStore[loginSessionId] = otp;

    // ✅ Log OTP properly
    console.log(`[OTP] Session ${loginSessionId} OTP: ${otp}`);

    return res.status(200).json({
      message: "OTP sent",
      loginSessionId,
    });
  } catch (error) {
    return res.status(500).json({
      status: "error",
      message: "Login failed",
    });
  }
});

/* ============================
   TASK 2: FIX OTP VERIFICATION
============================ */
app.post("/auth/verify-otp", (req, res) => {
  try {
    const { loginSessionId, otp } = req.body;

    if (!loginSessionId || !otp) {
      return res
        .status(400)
        .json({ error: "loginSessionId and otp required" });
    }

    const session = loginSessions[loginSessionId];

    if (!session) {
      return res.status(401).json({ error: "Invalid session" });
    }

    if (Date.now() > session.expiresAt) {
      delete loginSessions[loginSessionId];
      delete otpStore[loginSessionId];
      return res.status(401).json({ error: "Session expired" });
    }

    // ✅ Safe comparison (string-to-string)
    if (otp.toString() !== otpStore[loginSessionId]?.toString()) {
      return res.status(401).json({ error: "Invalid OTP" });
    }

    // ✅ Set session cookie
    res.cookie("session_token", loginSessionId, {
      httpOnly: true,
      secure: false,
      maxAge: 15 * 60 * 1000,
      sameSite: "lax",
    });

    delete otpStore[loginSessionId];

    return res.status(200).json({
      message: "OTP verified successfully",
    });
  } catch (error) {
    return res.status(500).json({
      status: "error",
      message: "OTP verification failed",
    });
  }
});

/* ============================
   TASK 3: FIX TOKEN GENERATION
============================ */
app.post("/auth/token", (req, res) => {
  try {
    // ✅ Read session from cookie instead of Authorization header
    const sessionId = req.cookies.session_token;

    if (!sessionId) {
      return res
        .status(401)
        .json({ error: "Unauthorized - valid session required" });
    }

    const session = loginSessions[sessionId];

    if (!session) {
      return res.status(401).json({ error: "Invalid session" });
    }

    const secret = process.env.JWT_SECRET || "default-secret-key";

    const accessToken = jwt.sign(
      {
        email: session.email,
        sessionId: sessionId,
      },
      secret,
      {
        expiresIn: "15m",
      }
    );

    return res.status(200).json({
      access_token: accessToken,
      expires_in: 900,
    });
  } catch (error) {
    return res.status(500).json({
      status: "error",
      message: "Token generation failed",
    });
  }
});

/* ============================
   PROTECTED ROUTE
============================ */
app.get("/protected", authMiddleware, (req, res) => {
  return res.json({
    message: "Access granted",
    user: req.user,
    success_flag: `FLAG-${Buffer.from(
      req.user.email + "_COMPLETED_ASSIGNMENT"
    ).toString("base64")}`,
  });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
