const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const {
  generateRegistrationChallenge,
  verifyRegistrationResponse,
  generateAuthenticationChallenge,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "10mb" }));
app.use(express.static(path.join(__dirname, "../public")));  // Serve index.html from public/

// Persistent users.json
const DATA_FILE = path.join(__dirname, "users.json");
let users = {};
if (fs.existsSync(DATA_FILE)) {
  users = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
}
function saveUsers() { fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2)); }

// Production Render config
const rpID = process.env.RENDER_EXTERNAL_HOSTNAME || "localhost";
const expectedOrigin = `https://${rpID}`;

// Debug users
app.get("/debug-users", (req, res) => res.json({ total: Object.keys(users).length, users }));

// Register
app.post("/register", (req, res) => {
  const { username } = req.body;
  users[username] = users[username] || { credentials: [] };
  const options = generateRegistrationChallenge({ rpName: "Fingerprint Demo", rpID, userID: username, userName: username });
  users[username].challenge = options.challenge;
  saveUsers();
  options.publicKey.authenticatorSelection = { authenticatorAttachment: "platform", userVerification: "required", requireResidentKey: true };
  res.json(options);
});

app.post("/register/verify", async (req, res) => {
  const { username, cred } = req.body;
  try {
    const verification = await verifyRegistrationResponse({ response: cred, expectedChallenge: users[username].challenge, expectedOrigin, expectedRPID: rpID });
    if (verification.verified) {
      users[username].credentials.push(verification.registrationInfo);
      delete users[username].challenge;
      saveUsers();
      res.json({ ok: true });
    }
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Login
app.post("/login", (req, res) => {
  const { username } = req.body;
  if (!users[username]?.credentials?.length) return res.status(400).json({ error: "Not registered" });
  const options = generateAuthenticationChallenge({ allowCredentials: users[username].credentials.map(c => ({ type: "public-key", id: c.credentialID })) });
  users[username].challenge = options.challenge;
  saveUsers();
  res.json(options);
});

app.post("/login/verify", async (req, res) => {
  const { username, cred } = req.body;
  const credInfo = users[username].credentials.find(c => c.credentialID === cred.id);
  try {
    const verification = await verifyAuthenticationResponse({ response: cred, expectedChallenge: users[username].challenge, expectedOrigin, expectedRPID: rpID, credentialPublicKey: credInfo.credentialPublicKey, credentialCounter: credInfo.counter || 0 });
    if (verification.verified) res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Catch-all for frontend routes
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "../public/index.html")));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Running on port ${PORT}`));
