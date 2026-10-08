const Database = require("better-sqlite3");

const db = new Database("ns_auto.db");

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`

-- USERS TABLE
CREATE TABLE IF NOT EXISTS users (
  user_id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  full_name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  profile_pic TEXT,
  role TEXT DEFAULT 'customer' CHECK (role IN ('customer', 'staff', 'admin')),
  is_active INTEGER DEFAULT 1,
  last_login DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- PRODUCTS TABLE
CREATE TABLE IF NOT EXISTS products (
  product_id INTEGER PRIMARY KEY AUTOINCREMENT,
  category TEXT NOT NULL CHECK (category IN ('car', 'mattress', 'other')),
  brand TEXT NOT NULL,
  model TEXT,
  year INTEGER,
  fuel_type TEXT,
  size TEXT,
  condition TEXT CHECK (condition IN ('new', 'used', 'refurbished')),
  mileage INTEGER,
  price REAL NOT NULL CHECK (price >= 0),
  description TEXT,
  image_url TEXT,
  user_id INTEGER NOT NULL,
  status TEXT DEFAULT 'active' CHECK (status IN ('active', 'sold', 'draft', 'archived')),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- MESSAGES TABLE
CREATE TABLE IF NOT EXISTS messages (
  message_id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL,
  receiver_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  status TEXT DEFAULT 'sent' CHECK (status IN ('sent', 'delivered', 'read')),
  FOREIGN KEY (sender_id) REFERENCES users(user_id) ON DELETE CASCADE,
  FOREIGN KEY (receiver_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- SESSIONS TABLE (for token-based auth)
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- INDEXES
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_products_category ON products(category);
CREATE INDEX IF NOT EXISTS idx_products_brand ON products(brand);
CREATE INDEX IF NOT EXISTS idx_products_status ON products(status);
CREATE INDEX IF NOT EXISTS idx_products_user_id ON products(user_id);
CREATE INDEX IF NOT EXISTS idx_products_created_at ON products(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id);

-- TRIGGERS FOR UPDATED_AT
CREATE TRIGGER IF NOT EXISTS update_users_timestamp
AFTER UPDATE ON users
BEGIN
  UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE user_id = NEW.user_id;
END;

CREATE TRIGGER IF NOT EXISTS update_products_timestamp
AFTER UPDATE ON products
BEGIN
  UPDATE products SET updated_at = CURRENT_TIMESTAMP WHERE product_id = NEW.product_id;
END;

`);

const insertDefaultAdmin = db.prepare(`
  INSERT OR IGNORE INTO users (username, full_name, email, password_hash, role)
  VALUES (?, ?, ?, ?, ?)
`);

const bcrypt = require("bcrypt");
const defaultPassword = bcrypt.hashSync("admin123", 10);
insertDefaultAdmin.run("admin", "NS Auto Admin", "admin@nsauto.com", defaultPassword, "admin");

module.exports = db;