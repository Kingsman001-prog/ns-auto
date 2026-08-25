// --- IMPORTS & SETUP ---
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const db = require("./db"); // SQLite database
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");
const cors = require("cors");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const port = process.env.PORT || 3000;
const uploadDir = path.join(__dirname, "uploads");

// --- INITIAL SETUP ---
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
  console.log(`Created uploads directory at ${uploadDir}`);
}

app.use(express.json());

// ✅ Explicitly allow your Netlify frontend
app.use(cors({
  origin: [
    "http://localhost:3000",
    "https://ns-auto-venture.netlify.app"
  ]
}));


app.use("/uploads", express.static(uploadDir));

// --- MULTER CONFIG ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),
});
const upload = multer({ storage });

// --- AUTH & USERS ---
app.post("/api/signup", async (req, res) => {
  try {
    const data = req.body;
    if (!data.username || !data.full_name || !data.email || !data.password) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    const existing = db.prepare("SELECT * FROM users WHERE email = ?").get(data.email);
    if (existing) {
      return res.status(400).json({ success: false, message: "Email already registered" });
    }

    const hash_password = await bcrypt.hash(data.password, 10);

    const stmt = db.prepare(`
      INSERT INTO users (username, full_name, email, password_hash, is_owner)
      VALUES (?, ?, ?, ?, ?)
    `);
    const info = stmt.run(data.username, data.full_name, data.email, hash_password, 0);

    res.status(200).json({
      success: true,
      message: "Signup successfully",
      user_id: info.lastInsertRowid,
      username: data.username,
      email: data.email,
    });
  } catch (e) {
    console.error("Signup error:", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/api/users", (req, res) => {
  try {
    const stmt = db.prepare("SELECT * FROM users");
    const users = stmt.all();
    res.json({ success: true, users });
  } catch (e) {
    console.error("Users fetch error:", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// --- PRODUCTS ---
app.get("/api/products", (req, res) => {
  try {
    const { category, brand, model, year, price_min, price_max } = req.query;

    let query = "SELECT * FROM products WHERE 1=1";
    const params = [];

    if (category) { query += " AND category = ?"; params.push(category); }
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

app.post("/api/products", upload.single("image"), (req, res) => {
  try {
    const prd = req.body;

    const user = db.prepare("SELECT * FROM users WHERE user_id = ?").get(prd.user_id);
    if (!user) {
      return res.status(400).json({ success: false, error: "User not found, please signup first" });
    }

    if (!user.is_owner) {
      return res.status(403).json({ success: false, error: "Only NS Auto Ventures owner can upload products" });
    }

    if (!req.file) {
      return res.status(400).json({ success: false, error: "No image uploaded" });
    }

    const imagePath = "/uploads/" + req.file.filename;

    const stmt = db.prepare(`
      INSERT INTO products (category, brand, model, year, fuel_type, size, price, description, image_url, user_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const info = stmt.run(
      prd.category,
      prd.brand,
      prd.model,
      prd.year,
      prd.fuel_type,
      prd.size,
      prd.price,
      prd.description,
      imagePath,
      prd.user_id
    );

    res.json({ success: true, product_id: info.lastInsertRowid, image_url: imagePath });
  } catch (e) {
    console.error("Product insert error:", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// --- SERVER START ---
server.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
