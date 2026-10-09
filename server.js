// --- IMPORTS ---
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const db = require("./db"); // SQLite database
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");
const cors = require("cors");
const crypto = require("crypto");

// --- APP & SERVER SETUP ---
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const port = process.env.PORT || 3000;
const uploadDir = path.join(__dirname, "uploads");
const staticDir = path.join(__dirname, "static");
const ownerEmail = process.env.OWNER_EMAIL?.trim().toLowerCase();
const ownerPassword = process.env.OWNER_PASSWORD;
const ownerUsername = process.env.OWNER_USERNAME || "owner";
const ownerFullName = process.env.OWNER_FULL_NAME || "NS Auto Venture Owner";
const publicBaseUrl = (process.env.PUBLIC_BASE_URL || "https://ns-auto.vercel.app").replace(/\/+$/, "");
const sessionDurationHours = 12;

// --- INITIALIZATION ---
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  console.log(`Created uploads directory at ${uploadDir}`);
}

if (ownerEmail && ownerPassword) {
  const passwordHash = bcrypt.hashSync(ownerPassword, 10);
  const existingOwner = db.prepare("SELECT user_id, password_hash FROM users WHERE email = ?").get(ownerEmail);

  if (existingOwner) {
    if (!bcrypt.compareSync(ownerPassword, existingOwner.password_hash)) {
      db.prepare("DELETE FROM sessions WHERE user_id = ?").run(existingOwner.user_id);
    }
    db.prepare(`
      UPDATE users
      SET full_name = ?, password_hash = ?, role = 'admin', is_active = 1
      WHERE user_id = ?
    `).run(ownerFullName, passwordHash, existingOwner.user_id);
  } else {
    let username = ownerUsername;
    let suffix = 1;
    while (db.prepare("SELECT user_id FROM users WHERE username = ?").get(username)) {
      username = `${ownerUsername}-${suffix++}`;
    }
    db.prepare(`
      INSERT INTO users (username, full_name, email, password_hash, role)
      VALUES (?, ?, ?, ?, 'admin')
    `).run(username, ownerFullName, ownerEmail, passwordHash);
  }
} else {
  console.warn("Owner login is disabled. Set OWNER_EMAIL and OWNER_PASSWORD to enable it.");
}

app.use(express.json());

// ✅ Allow Netlify frontend
app.use(cors({
  origin: "https://ns-auto-venture.netlify.app",
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));

app.get("/", (req, res) => res.sendFile(path.join(staticDir, "index.html")));
app.get("/signup", (req, res) => res.sendFile(path.join(staticDir, "signup.html")));
app.get("/upload", (req, res) => res.sendFile(path.join(staticDir, "upload.html")));
app.get("/mattress", (req, res) => res.sendFile(path.join(staticDir, "mattress.html")));
app.get("/product", (req, res) => res.sendFile(path.join(staticDir, "product.html")));
app.use(express.static(staticDir));

// Serve uploaded files
app.use("/uploads", express.static(uploadDir));

// --- MULTER CONFIG ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const extensionByType = { "image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp" };
    cb(null, `${crypto.randomUUID()}${extensionByType[file.mimetype]}`);
  },
});
const allowedImageTypes = new Set(["image/jpeg", "image/png", "image/webp"]);
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!allowedImageTypes.has(file.mimetype)) {
      const error = new Error("Only JPEG, PNG, and WebP images are allowed");
      error.code = "INVALID_IMAGE_TYPE";
      return cb(error);
    }
    cb(null, true);
  },
});

function removeUploadedFile(filePath) {
  try {
    fs.unlinkSync(filePath);
  } catch (e) {
    if (e.code !== "ENOENT") {
      console.error("Uploaded image cleanup error:", e);
    }
  }
}

function getOwnerFromRequest(req) {
  if (!ownerEmail || !ownerPassword) {
    return null;
  }

  const authorization = req.get("authorization") || "";
  const match = authorization.match(/^Bearer ([A-Za-z0-9_-]+)$/);
  if (!match) {
    return null;
  }

  const sessionId = crypto.createHash("sha256").update(match[1]).digest("hex");
  return db.prepare(`
    SELECT users.user_id, users.username, users.email, sessions.session_id
    FROM sessions
    JOIN users ON users.user_id = sessions.user_id
    WHERE sessions.session_id = ?
      AND sessions.expires_at > datetime('now')
      AND users.email = ?
      AND users.role = 'admin'
      AND users.is_active = 1
  `).get(sessionId, ownerEmail) || null;
}

function requireOwner(req, res, next) {
  const owner = getOwnerFromRequest(req);
  if (!owner) {
    return res.status(ownerEmail && ownerPassword ? 401 : 503).json({
      success: false,
      message: ownerEmail && ownerPassword
        ? "Owner login required"
        : "Owner login is not configured",
    });
  }

  req.owner = owner;
  next();
}

// --- AUTH & USERS ROUTES ---
app.post("/api/signup", async (req, res) => {
  try {
    const username = typeof req.body.username === "string" ? req.body.username.trim() : "";
    const fullName = typeof req.body.full_name === "string" ? req.body.full_name.trim() : "";
    const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    if (!username || !fullName || !email || !password) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }
    const existing = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    if (existing) {
      return res.status(400).json({ success: false, message: "Email already registered" });
    }

    const hash_password = await bcrypt.hash(password, 10);

    const stmt = db.prepare(`
      INSERT INTO users (username, full_name, email, password_hash)
      VALUES (?, ?, ?, ?)
    `);
    const info = stmt.run(username, fullName, email, hash_password);

    res.status(200).json({
      success: true,
      message: "Signup successfully",
      user_id: info.lastInsertRowid,
      username,
      email,
    });
  } catch (e) {
    console.error("Signup error:", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/api/owner/login", (req, res) => {
  try {
    if (!ownerEmail || !ownerPassword) {
      return res.status(503).json({ success: false, message: "Owner login is not configured" });
    }

    const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    if (email !== ownerEmail || !password) {
      return res.status(401).json({ success: false, message: "Invalid owner email or password" });
    }

    const user = db.prepare(`
      SELECT user_id, username, email, password_hash
      FROM users
      WHERE email = ? AND role = 'admin' AND is_active = 1
    `).get(ownerEmail);

    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ success: false, message: "Invalid owner email or password" });
    }

    db.prepare("DELETE FROM sessions WHERE expires_at <= datetime('now')").run();
    const token = crypto.randomBytes(32).toString("base64url");
    const sessionId = crypto.createHash("sha256").update(token).digest("hex");
    db.prepare(`
      INSERT INTO sessions (session_id, user_id, expires_at)
      VALUES (?, ?, datetime('now', ?))
    `).run(sessionId, user.user_id, `+${sessionDurationHours} hours`);

    res.json({
      success: true,
      token,
      expires_in: sessionDurationHours * 60 * 60,
      owner: { username: user.username, email: user.email },
    });
  } catch (e) {
    console.error("Owner login error:", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/api/owner/session", requireOwner, (req, res) => {
  res.json({
    success: true,
    owner: { username: req.owner.username, email: req.owner.email },
  });
});

app.post("/api/owner/logout", requireOwner, (req, res) => {
  try {
    db.prepare("DELETE FROM sessions WHERE session_id = ?").run(req.owner.session_id);
    res.json({ success: true });
  } catch (e) {
    console.error("Owner logout error:", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/api/users", (req, res) => {
  try {
    const stmt = db.prepare(`
      SELECT user_id, username, full_name, email, profile_pic, role, created_at
      FROM users
    `);
    const users = stmt.all();
    res.json({ success: true, users });
  } catch (e) {
    console.error("Users fetch error:", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// --- PRODUCTS ROUTES ---
app.get("/api/products/:productId", (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.productId)) {
      return res.status(400).json({ success: false, message: "Invalid product ID" });
    }

    const product = db.prepare("SELECT * FROM products WHERE product_id = ?").get(Number(req.params.productId));
    if (!product) {
      return res.status(404).json({ success: false, message: "Product not found" });
    }

    res.json({ success: true, product });
  } catch (e) {
    console.error("Product fetch error:", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/api/products", (req, res) => {
  try {
    const { category, brand, model, search, year, price_min, price_max } = req.query;

    let query = "SELECT * FROM products WHERE 1=1";
    const params = [];

    if (category) { query += " AND category = ?"; params.push(category); }
    if (search) {
      query += " AND (brand LIKE ? OR model LIKE ? OR size LIKE ?)";
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }
    if (brand) { query += " AND brand LIKE ?"; params.push(`%${brand}%`); }
    if (model) { query += " AND model LIKE ?"; params.push(`%${model}%`); }
    if (year) { query += " AND year = ?"; params.push(year); }
    if (price_min) { query += " AND price >= ?"; params.push(price_min); }
    if (price_max) { query += " AND price <= ?"; params.push(price_max); }

    const stmt = db.prepare(query);
    const products = stmt.all(...params);

    res.json({ success: true, products });
  } catch (e) {
    console.error("Products fetch error:", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/api/products", requireOwner, upload.single("image"), (req, res) => {
  try {
    const prd = req.body;
    const category = typeof prd.category === "string" ? prd.category : "";
    const brand = typeof prd.brand === "string" ? prd.brand.trim() : "";
    const price = typeof prd.price === "string" && prd.price.trim() ? Number(prd.price) : NaN;
    if (!["car", "mattress", "other"].includes(category) || !brand || !Number.isFinite(price) || price < 0) {
      if (req.file) removeUploadedFile(req.file.path);
      return res.status(400).json({ success: false, error: "A valid category, brand, and non-negative price are required" });
    }

    if (!req.file) {
      return res.status(400).json({ success: false, error: "No image uploaded" });
    }

    const imagePath = `${publicBaseUrl}/uploads/${req.file.filename}`;
    const year = prd.year ? Number(prd.year) : null;
    if (year !== null && (!Number.isInteger(year) || year < 1886 || year > new Date().getFullYear() + 1)) {
      removeUploadedFile(req.file.path);
      return res.status(400).json({ success: false, error: "Year must be a valid vehicle year" });
    }

    const stmt = db.prepare(`
      INSERT INTO products (category, brand, model, year, fuel_type, size, price, description, image_url, user_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const info = stmt.run(
      category,
      brand,
      prd.model || null,
      year,
      prd.fuel_type || null,
      prd.size || null,
      price,
      prd.description || null,
      imagePath,
      req.owner.user_id
    );

    res.json({ success: true, product_id: info.lastInsertRowid, image_url: imagePath });
  } catch (e) {
    console.error("Product insert error:", e);
    if (req.file) removeUploadedFile(req.file.path);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || err.code === "INVALID_IMAGE_TYPE") {
    const status = err.code === "LIMIT_FILE_SIZE" ? 413 : 400;
    return res.status(status).json({ success: false, message: err.message || "Upload failed" });
  }
  next();
});

// --- SERVER START ---
server.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
