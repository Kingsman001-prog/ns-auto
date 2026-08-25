const Database = require("better-sqlite3");

// Create or open database file
const db = new Database("ns_auto.db");

// Initialize tables if not exist
db.exec(`

-- USERS TABLE
CREATE TABLE IF NOT EXISTS users (
  user_id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  full_name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  profile_pic TEXT,
  status TEXT DEFAULT 'offline',
  is_owner INTEGER DEFAULT 0 -- 0 = normal user, 1 = NS Auto Ventures owner
);

-- PRODUCTS TABLE
CREATE TABLE IF NOT EXISTS products (
  product_id INTEGER PRIMARY KEY AUTOINCREMENT,
  category TEXT NOT NULL, -- car or mattress
  brand TEXT NOT NULL,
  model TEXT,
  year INTEGER,
  fuel_type TEXT,
  size TEXT,
  price REAL NOT NULL,
  description TEXT,
  image_url TEXT,
  user_id INTEGER NOT NULL, -- link to users table
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- MESSAGES TABLE
CREATE TABLE IF NOT EXISTS messages (
  message_id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL,
  receiver_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  status TEXT DEFAULT 'sent',
  FOREIGN KEY (sender_id) REFERENCES users(user_id),
  FOREIGN KEY (receiver_id) REFERENCES users(user_id)
);

`);

module.exports = db;
