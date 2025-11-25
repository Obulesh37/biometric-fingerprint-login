const express = require("express");
const cors = require("cors");
const { generateRegistrationChallenge, verifyRegistrationResponse, generateAuthenticationChallenge, verifyAuthenticationResponse } = require("@simplewebauthn/server");

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "10mb" }));

// In-memory database (no MongoDB needed)
const users = {};

// Debug route — SEE ALL USER DATA ANYTIME
app.get("/debug-users", (req, res) => {
  res.json({
    message: "All registered users (in-memory)",
    total: Object.keys(users).length,
    users: users
  });
});

const rpID = "localhost";
const origin = "http://127.0.0.1:5500";  // Works when opening HTML directly

app.post("/register", (req, res) => {
  const { username } = req.body;
  users[username] = users[username] || { credentials: [] };

  const options = generateRegistrationChallenge({
    rpName: "Fingerprint Login Demo",
    rpID,
    userID: username,
    userName: username,
  });

  users[username].challenge = options.challenge;
  options.publicKey.authenticatorSelection = {
    authenticatorAttachment: "platform",
    userVerification: "required",
    requireResidentKey: true
  };

  res.json(options);
});

app.post("/register/verify", async (req, res) => {
  const { username, cred } = req.body;
  try {
    const verification = await verifyRegistrationResponse({
      response: cred,
      expectedChallenge: users[username].challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (verification.verified) {
      users[username].credentials.push(verification.registrationInfo);
      delete users[username].challenge;

      console.log("NEW USER REGISTERED:", username);
      console.log("TOTAL USERS:", Object.keys(users).length);
      console.log("FULL DATA → http://localhost:5000/debug-users");

      res.json({ ok: true });
    }
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post("/login", (req, res) => {
  const { username } = req.body;
  if (!users[username]?.credentials?.length) return res.status(400).json({ error: "Not registered" });

  const options = generateAuthenticationChallenge({
    allowCredentials: users[username].credentials.map(c => ({ type: "public-key", id: c.credentialID }))
  });
  users[username].challenge = options.challenge;
  res.json(options);
});

app.post("/login/verify", async (req, res) => {
  const { username, cred } = req.body;
  const credInfo = users[username].credentials.find(c => c.credentialID === cred.id);
  try {
    const verification = await verifyAuthenticationResponse({
      response: cred,
      expectedChallenge: users[username].challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credentialPublicKey: credInfo.credentialPublicKey,
      credentialCounter: credInfo.counter || 0,
    });
    if (verification.verified) res.json({ ok: true, msg: "Login Success!" });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.listen(5000, () => {
  console.log("Server running on http://localhost:5000");
  console.log("SEE ALL USERS → http://localhost:5000/debug-users");
});
// ... (keep existing code)

// Update CORS for production (replace with your frontend URL after deploy)
app.use(cors({ origin: "*" }));  // Temporary; change to 'https://your-frontend.onrender.com'

// For in-memory persistence (optional: saves to JSON file on restarts)
const fs = require('fs');
// Load on startup
if (fs.existsSync('users.json')) {
  Object.assign(users, JSON.parse(fs.readFileSync('users.json')));
}
// Save on changes (add to register/verify and login/verify success blocks)
fs.writeFileSync('users.json', JSON.stringify(users));

// ... (rest unchanged)