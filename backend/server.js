const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 5000;
const SECRET_KEY = "fitgaleria_secret_2024";
const DB_PATH = path.join(__dirname, "fitgaleria.db");

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "../frontend")));

// ============= DATABASE SETUP =============
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error("❌ Database connection error:", err.message);
  } else {
    console.log("✅ Connected to SQLite database");
    initializeDatabase();
  }
});

// Initialize database tables
function initializeDatabase() {
  // Users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) console.error("Error creating users table:", err);
    else console.log("✅ Users table ready");
  });

  // Products table
    db.run(`
      CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        image TEXT,
        description TEXT,
        category TEXT DEFAULT 'General',
        stock INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `, (err) => {
      if (err) console.error("Error creating products table:", err);
      else {
        console.log("✅ Products table ready");
        // Add category column to existing table if it doesn't exist
        db.run(`ALTER TABLE products ADD COLUMN category TEXT DEFAULT 'General'`, (err) => {
          if (err && !err.message.includes('duplicate column name')) {
            console.error("Error adding category column:", err);
          } else {
            console.log("✅ Category column ready");
          }
        });
      }
    });

  // Cart table
  db.run(`
    CREATE TABLE IF NOT EXISTS cart (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      product_id INTEGER,
      quantity INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id),
      FOREIGN KEY (product_id) REFERENCES products (id)
    )
  `, (err) => {
    if (err) console.error("Error creating cart table:", err);
    else console.log("✅ Cart table ready");
  });

  // Orders table
  db.run(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      total_amount DECIMAL(10,2),
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `, (err) => {
    if (err) console.error("Error creating orders table:", err);
    else console.log("✅ Orders table ready");
  });

  // Order items table
  db.run(`
    CREATE TABLE IF NOT EXISTS order_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER,
      product_id INTEGER,
      quantity INTEGER,
      price DECIMAL(10,2),
      FOREIGN KEY (order_id) REFERENCES orders (id),
      FOREIGN KEY (product_id) REFERENCES products (id)
    )
  `, (err) => {
    if (err) console.error("Error creating order_items table:", err);
    else console.log("✅ Order items table ready");
  });

  // NEW: Wishlist table
  db.run(`
    CREATE TABLE IF NOT EXISTS wishlist (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      product_id INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id),
      FOREIGN KEY (product_id) REFERENCES products (id),
      UNIQUE(user_id, product_id)
    )
  `, (err) => {
    if (err) console.error("Error creating wishlist table:", err);
    else console.log("✅ Wishlist table ready");
    
    // Insert default data after all tables are created
    insertDefaultData();
  });
}

// Insert default users and products
function insertDefaultData() {
  // Hash passwords
  const saltRounds = 10;
  
  // Default admin user
  bcrypt.hash("1234", saltRounds, (err, adminHash) => {
    if (err) {
      console.error("Error hashing admin password:", err);
      return;
    }
    
    db.run(`
      INSERT OR IGNORE INTO users (username, password, role) 
      VALUES (?, ?, ?)
    `, ["fitadmin", adminHash, "admin"], function(err) {
      if (err) console.error("Error inserting admin:", err);
      else console.log("✅ Admin user created");
    });
  });

  // Default regular user
  bcrypt.hash("abcd", saltRounds, (err, userHash) => {
    if (err) {
      console.error("Error hashing user password:", err);
      return;
    }
    
    db.run(`
      INSERT OR IGNORE INTO users (username, password, role) 
      VALUES (?, ?, ?)
    `, ["rimon", userHash, "user"], function(err) {
      if (err) console.error("Error inserting user:", err);
      else console.log("✅ Regular user created");
    });
  });

  // Default products
  const products = [
    { 
      name: "Weightlifting Gym Grip", 
      price: 390, 
      image: "img/product1.png", 
      description: "Professional weightlifting grips for better grip and protection", 
      category: "Accessories",
      stock: 50 
    },
    { 
      name: "Baki Hanma Drop Shoulder", 
      price: 550, 
      image: "img/pic1.png", 
      description: "Comfortable drop shoulder t-shirt for men", 
      category: "Men",
      stock: 30 
    },
    { 
      name: "Combo!", 
      price: 890, 
      image: "img/pic2.png", 
      description: "Special combo package with multiple items", 
      category: "Equipment",
      stock: 20 
    },
    // ADD MORE SAMPLE PRODUCTS FOR BETTER DEMO
    {
      name: "Women's Yoga Leggings",
      price: 450,
      image: "img/product1.png", // Use existing image for demo
      description: "High-waisted yoga leggings for women",
      category: "Women",
      stock: 25
    },
    {
      name: "Men's Tank Top",
      price: 350,
      image: "img/pic1.png",
      description: "Breathable cotton tank top for workouts",
      category: "Men",
      stock: 40
    },
    {
      name: "Resistance Bands Set",
      price: 750,
      image: "img/pic2.png",
      description: "Complete set of resistance bands for home workouts",
      category: "Equipment",
      stock: 15
    },
    {
      name: "Women's Sports Bra",
      price: 420,
      image: "img/product1.png",
      description: "High-support sports bra for intense workouts",
      category: "Women",
      stock: 35
    },
    {
      name: "Protein Shaker Bottle",
      price: 180,
      image: "img/pic2.png",
      description: "BPA-free protein shaker with mixing ball",
      category: "Accessories",
      stock: 60
    }
  ];

  products.forEach(product => {
    db.run(`
      INSERT OR IGNORE INTO products (name, price, image, description, category, stock) 
      VALUES (?, ?, ?, ?, ?, ?)
    `, [product.name, product.price, product.image, product.description, product.category, product.stock], function(err) {
      if (err) console.error("Error inserting product:", err);
    });
  });
  
  console.log("✅ Default products with categories created");
}

// ============= MIDDLEWARE =============
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.status(401).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Invalid token" });
    }
    req.user = decoded;
    next();
  });
}

// ============= AUTH ROUTES =============

// User signup
app.post("/api/signup", async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run(`
      INSERT INTO users (username, password, role) 
      VALUES (?, ?, ?)
    `, [username, hashedPassword, "user"], function(err) {
      if (err) {
        if (err.message.includes("UNIQUE constraint failed")) {
          return res.status(400).json({ message: "Username already exists" });
        }
        return res.status(500).json({ message: "Database error" });
      }
      
      console.log(`✅ New user registered: ${username}`);
      res.json({ message: "Signup successful", userId: this.lastID });
    });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// User login
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required" });
  }

  db.get(`
    SELECT id, username, password, role 
    FROM users 
    WHERE username = ?
  `, [username], async (err, user) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    try {
      const passwordMatch = await bcrypt.compare(password, user.password);
      
      if (!passwordMatch) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      const token = jwt.sign(
        { userId: user.id, username: user.username, role: user.role },
        SECRET_KEY,
        { expiresIn: "24h" }
      );

      console.log(`✅ User logged in: ${username} (${user.role})`);
      res.json({
        token,
        role: user.role,
        username: user.username,
        userId: user.id,
        redirect: user.role === "admin" ? "/admin.html" : "/shop.html"
      });
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({ message: "Server error" });
    }
  });
});

// ============= PRODUCT ROUTES =============

// Get all products
app.get("/api/products", (req, res) => {
  const category = req.query.category;
  
  let query = `
    SELECT id, name, price, image, description, category, stock 
    FROM products 
  `;
  let params = [];
  
  if (category && category !== 'all') {
    query += `WHERE category = ? `;
    params.push(category);
  }
  
  query += `ORDER BY id`;

  db.all(query, params, (err, products) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    
    res.json(products);
  });
});

// Get single product
app.get("/api/products/:id", (req, res) => {
  const productId = req.params.id;
  
  db.get(`
    SELECT id, name, price, image, description, stock 
    FROM products 
    WHERE id = ?
  `, [productId], (err, product) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    
    if (!product) {
      return res.status(404).json({ message: "Product not found" });
    }
    
    res.json(product);
  });
});
app.get("/api/categories", (req, res) => {
  db.all(`
    SELECT DISTINCT category 
    FROM products 
    WHERE category IS NOT NULL 
    ORDER BY category
  `, [], (err, categories) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    
    const categoryList = categories.map(row => row.category);
    res.json(categoryList);
  });
});


// ============= CART ROUTES =============

// Add to cart
app.post("/api/cart", verifyToken, (req, res) => {
  const { productId, quantity = 1 } = req.body;
  const userId = req.user.userId;

  if (!productId) {
    return res.status(400).json({ message: "Product ID required" });
  }

  // Check if product exists and has stock
  db.get(`
    SELECT id, name, price, stock 
    FROM products 
    WHERE id = ?
  `, [productId], (err, product) => {
    if (err) {
      return res.status(500).json({ message: "Database error" });
    }
    
    if (!product) {
      return res.status(404).json({ message: "Product not found" });
    }
    
    if (product.stock < quantity) {
      return res.status(400).json({ message: "Insufficient stock" });
    }

    // Check if item already in cart
    db.get(`
      SELECT id, quantity 
      FROM cart 
      WHERE user_id = ? AND product_id = ?
    `, [userId, productId], (err, existingItem) => {
      if (err) {
        return res.status(500).json({ message: "Database error" });
      }

      if (existingItem) {
        // Update quantity
        const newQuantity = existingItem.quantity + quantity;
        
        db.run(`
          UPDATE cart 
          SET quantity = ? 
          WHERE id = ?
        `, [newQuantity, existingItem.id], (err) => {
          if (err) {
            return res.status(500).json({ message: "Database error" });
          }
          
          console.log(`✅ Cart updated for user ${userId}: product ${productId}`);
          res.json({ message: "Cart updated", productName: product.name });
        });
      } else {
        // Add new item
        db.run(`
          INSERT INTO cart (user_id, product_id, quantity) 
          VALUES (?, ?, ?)
        `, [userId, productId, quantity], (err) => {
          if (err) {
            return res.status(500).json({ message: "Database error" });
          }
          
          console.log(`✅ Item added to cart for user ${userId}: product ${productId}`);
          res.json({ message: "Added to cart", productName: product.name });
        });
      }
    });
  });
});

// Get user's cart
app.get("/api/cart", verifyToken, (req, res) => {
  const userId = req.user.userId;

  db.all(`
    SELECT 
      c.id as cart_id,
      c.quantity,
      p.id as product_id,
      p.name,
      p.price,
      p.image,
      (p.price * c.quantity) as subtotal
    FROM cart c
    JOIN products p ON c.product_id = p.id
    WHERE c.user_id = ?
    ORDER BY c.created_at DESC
  `, [userId], (err, cartItems) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }

    const total = cartItems.reduce((sum, item) => sum + item.subtotal, 0);
    
    res.json({
      cart: cartItems,
      total: total,
      itemCount: cartItems.reduce((sum, item) => sum + item.quantity, 0)
    });
  });
});

// Update cart item quantity
app.put("/api/cart/:cartId", verifyToken, (req, res) => {
  const cartId = req.params.cartId;
  const { quantity } = req.body;
  const userId = req.user.userId;

  if (!quantity || quantity < 1) {
    return res.status(400).json({ message: "Invalid quantity" });
  }

  db.run(`
    UPDATE cart 
    SET quantity = ? 
    WHERE id = ? AND user_id = ?
  `, [quantity, cartId, userId], function(err) {
    if (err) {
      return res.status(500).json({ message: "Database error" });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ message: "Cart item not found" });
    }
    
    res.json({ message: "Cart updated" });
  });
});

// Remove from cart
app.delete("/api/cart/:cartId", verifyToken, (req, res) => {
  const cartId = req.params.cartId;
  const userId = req.user.userId;

  db.run(`
    DELETE FROM cart 
    WHERE id = ? AND user_id = ?
  `, [cartId, userId], function(err) {
    if (err) {
      return res.status(500).json({ message: "Database error" });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ message: "Cart item not found" });
    }
    
    console.log(`✅ Item removed from cart: ${cartId}`);
    res.json({ message: "Item removed from cart" });
  });
});

// Clear cart
app.delete("/api/cart", verifyToken, (req, res) => {
  const userId = req.user.userId;

  db.run(`
    DELETE FROM cart 
    WHERE user_id = ?
  `, [userId], function(err) {
    if (err) {
      return res.status(500).json({ message: "Database error" });
    }
    
    console.log(`✅ Cart cleared for user: ${userId}`);
    res.json({ message: "Cart cleared" });
  });
});

// ======================================= ORDER ROUTES ==================================


// Get detailed order history for a user
app.get("/api/orders/history", verifyToken, (req, res) => {
  const userId = req.user.userId;

  db.all(`
    SELECT 
      o.id,
      o.total_amount,
      o.status,
      o.created_at,
      COUNT(oi.id) as item_count
    FROM orders o
    LEFT JOIN order_items oi ON o.id = oi.order_id
    WHERE o.user_id = ?
    GROUP BY o.id
    ORDER BY o.created_at DESC
  `, [userId], (err, orders) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }

    res.json(orders);
  });
});

// Get detailed order with items
app.get("/api/orders/:orderId/details", verifyToken, (req, res) => {
  const orderId = req.params.orderId;
  const userId = req.user.userId;

  // First verify the order belongs to the user
  db.get(`
    SELECT id FROM orders 
    WHERE id = ? AND user_id = ?
  `, [orderId, userId], (err, order) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }

    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }

    // Get order details with items
    db.all(`
      SELECT 
        o.id as order_id,
        o.total_amount,
        o.status,
        o.created_at as order_date,
        oi.quantity,
        oi.price as item_price,
        p.name as product_name,
        p.image as product_image,
        p.id as product_id
      FROM orders o
      LEFT JOIN order_items oi ON o.id = oi.order_id
      LEFT JOIN products p ON oi.product_id = p.id
      WHERE o.id = ?
      ORDER BY oi.id
    `, [orderId], (err, orderDetails) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ message: "Database error" });
      }

      // Group the results
      const orderInfo = {
        id: orderDetails[0]?.order_id,
        total_amount: orderDetails[0]?.total_amount,
        status: orderDetails[0]?.status,
        order_date: orderDetails[0]?.order_date,
        items: orderDetails.map(item => ({
          product_id: item.product_id,
          product_name: item.product_name,
          product_image: item.product_image,
          quantity: item.quantity,
          price: item.item_price,
          subtotal: item.quantity * item.item_price
        }))
      };

      res.json(orderInfo);
    });
  });
});

// Update order status (Admin only)
app.put("/api/orders/:orderId/status", verifyToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access required" });
  }

  const orderId = req.params.orderId;
  const { status } = req.body;

  // Validate status
  const validStatuses = ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'];
  if (!validStatuses.includes(status.toLowerCase())) {
    return res.status(400).json({ message: "Invalid status" });
  }

  db.run(`
    UPDATE orders 
    SET status = ? 
    WHERE id = ?
  `, [status.toLowerCase(), orderId], function(err) {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }

    if (this.changes === 0) {
      return res.status(404).json({ message: "Order not found" });
    }

    console.log(`✅ Order ${orderId} status updated to: ${status}`);
    res.json({ message: "Order status updated successfully" });
  });
});

// Cancel order (User can cancel only pending orders)
app.put("/api/orders/:orderId/cancel", verifyToken, (req, res) => {
  const orderId = req.params.orderId;
  const userId = req.user.userId;

  // Check if order exists and belongs to user and is still pending
  db.get(`
    SELECT id, status 
    FROM orders 
    WHERE id = ? AND user_id = ?
  `, [orderId, userId], (err, order) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }

    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }

    if (order.status !== 'pending') {
      return res.status(400).json({ message: "Only pending orders can be cancelled" });
    }

    // Update status to cancelled
    db.run(`
      UPDATE orders 
      SET status = 'cancelled' 
      WHERE id = ?
    `, [orderId], function(err) {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ message: "Database error" });
      }

      console.log(`✅ Order ${orderId} cancelled by user ${userId}`);
      res.json({ message: "Order cancelled successfully" });
    });
  });
});

// Also update the existing orders route to include order items summary
app.get("/api/orders", verifyToken, (req, res) => {
  const userId = req.user.userId;

  db.all(`
    SELECT 
      o.id,
      o.total_amount,
      o.status,
      o.created_at,
      COUNT(oi.id) as item_count,
      GROUP_CONCAT(p.name, ', ') as product_names
    FROM orders o
    LEFT JOIN order_items oi ON o.id = oi.order_id
    LEFT JOIN products p ON oi.product_id = p.id
    WHERE o.user_id = ?
    GROUP BY o.id
    ORDER BY o.created_at DESC
  `, [userId], (err, orders) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }

    res.json(orders);
  });
});


// Create order
app.post("/api/orders", verifyToken, (req, res) => {
  const userId = req.user.userId;

  // Get cart items
  db.all(`
    SELECT 
      c.product_id,
      c.quantity,
      p.name,
      p.price,
      (p.price * c.quantity) as subtotal
    FROM cart c
    JOIN products p ON c.product_id = p.id
    WHERE c.user_id = ?
  `, [userId], (err, cartItems) => {
    if (err) {
      return res.status(500).json({ message: "Database error" });
    }

    if (cartItems.length === 0) {
      return res.status(400).json({ message: "Cart is empty" });
    }

    const totalAmount = cartItems.reduce((sum, item) => sum + item.subtotal, 0);

    // Create order
    db.run(`
      INSERT INTO orders (user_id, total_amount, status) 
      VALUES (?, ?, ?)
    `, [userId, totalAmount, "pending"], function(err) {
      if (err) {
        return res.status(500).json({ message: "Database error" });
      }

      const orderId = this.lastID;

      // Insert order items
      const insertPromises = cartItems.map(item => {
        return new Promise((resolve, reject) => {
          db.run(`
            INSERT INTO order_items (order_id, product_id, quantity, price) 
            VALUES (?, ?, ?, ?)
          `, [orderId, item.product_id, item.quantity, item.price], (err) => {
            if (err) reject(err);
            else resolve();
          });
        });
      });

      Promise.all(insertPromises)
        .then(() => {
          // Clear cart
          db.run(`DELETE FROM cart WHERE user_id = ?`, [userId], (err) => {
            if (err) console.error("Error clearing cart:", err);
          });

          console.log(`✅ Order created: ${orderId} for user ${userId}`);
          res.json({
            message: "Order created successfully",
            orderId: orderId,
            totalAmount: totalAmount
          });
        })
        .catch(error => {
          console.error("Error creating order items:", error);
          res.status(500).json({ message: "Error creating order" });
        });
    });
  });
});

// Get user's orders
app.get("/api/orders", verifyToken, (req, res) => {
  const userId = req.user.userId;

  db.all(`
    SELECT 
      o.id,
      o.total_amount,
      o.status,
      o.created_at,
      COUNT(oi.id) as item_count
    FROM orders o
    LEFT JOIN order_items oi ON o.id = oi.order_id
    WHERE o.user_id = ?
    GROUP BY o.id
    ORDER BY o.created_at DESC
  `, [userId], (err, orders) => {
    if (err) {
      return res.status(500).json({ message: "Database error" });
    }

    res.json(orders);
  });
});

// ============= WISHLIST ROUTES =============

// Add to wishlist
app.post("/api/wishlist", verifyToken, (req, res) => {
  const { productId } = req.body;
  const userId = req.user.userId;

  if (!productId) {
    return res.status(400).json({ message: "Product ID required" });
  }

  db.run(`
    INSERT OR IGNORE INTO wishlist (user_id, product_id) 
    VALUES (?, ?)
  `, [userId, productId], function(err) {
    if (err) {
      return res.status(500).json({ message: "Database error" });
    }
    
    if (this.changes === 0) {
      return res.status(400).json({ message: "Item already in wishlist" });
    }
    
    console.log(`✅ Item added to wishlist for user ${userId}: product ${productId}`);
    res.json({ message: "Added to wishlist" });
  });
});

// Get user's wishlist
app.get("/api/wishlist", verifyToken, (req, res) => {
  const userId = req.user.userId;

  db.all(`
    SELECT 
      w.id as wishlist_id,
      p.id as product_id,
      p.name,
      p.price,
      p.image,
      p.description,
      w.created_at
    FROM wishlist w
    JOIN products p ON w.product_id = p.id
    WHERE w.user_id = ?
    ORDER BY w.created_at DESC
  `, [userId], (err, wishlistItems) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }

    res.json(wishlistItems);
  });
});

// Remove from wishlist
app.delete("/api/wishlist/:productId", verifyToken, (req, res) => {
  const productId = req.params.productId;
  const userId = req.user.userId;

  db.run(`
    DELETE FROM wishlist 
    WHERE user_id = ? AND product_id = ?
  `, [userId, productId], function(err) {
    if (err) {
      return res.status(500).json({ message: "Database error" });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ message: "Item not found in wishlist" });
    }
    
    console.log(`✅ Item removed from wishlist: ${productId}`);
    res.json({ message: "Item removed from wishlist" });
  });
});

// ============= ADMIN ROUTES =============

// Admin dashboard stats
app.get("/api/admin/stats", verifyToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access required" });
  }

  // Get all stats in parallel
  const queries = {
    totalUsers: new Promise((resolve, reject) => {
      db.get("SELECT COUNT(*) as count FROM users", (err, result) => {
        if (err) reject(err);
        else resolve(result.count);
      });
    }),
    
    totalProducts: new Promise((resolve, reject) => {
      db.get("SELECT COUNT(*) as count FROM products", (err, result) => {
        if (err) reject(err);
        else resolve(result.count);
      });
    }),
    
    cartItems: new Promise((resolve, reject) => {
      db.get("SELECT SUM(quantity) as total FROM cart", (err, result) => {
        if (err) reject(err);
        else resolve(result.total || 0);
      });
    }),
    
    totalRevenue: new Promise((resolve, reject) => {
      db.get("SELECT SUM(total_amount) as total FROM orders WHERE status != 'cancelled'", (err, result) => {
        if (err) reject(err);
        else resolve(result.total || 0);
      });
    }),

    totalOrders: new Promise((resolve, reject) => {
      db.get("SELECT COUNT(*) as count FROM orders", (err, result) => {
        if (err) reject(err);
        else resolve(result.count);
      });
    }),

    // NEW: Wishlist stats
    totalWishlistItems: new Promise((resolve, reject) => {
      db.get("SELECT COUNT(*) as count FROM wishlist", (err, result) => {
        if (err) reject(err);
        else resolve(result.count);
      });
    })
  };

  Promise.all(Object.values(queries))
    .then(([totalUsers, totalProducts, cartItems, totalRevenue, totalOrders, totalWishlistItems]) => {
      res.json({
        totalUsers,
        totalProducts,
        cartItems,
        totalRevenue: parseFloat(totalRevenue || 0),
        totalOrders,
        totalWishlistItems // NEW field
      });
    })
    .catch(error => {
      console.error("Error fetching admin stats:", error);
      res.status(500).json({ message: "Database error" });
    });
});

// Get all users (admin only)
app.get("/api/admin/users", verifyToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access required" });
  }

  db.all(`
    SELECT id, username, role, created_at 
    FROM users 
    ORDER BY created_at DESC
  `, [], (err, users) => {
    if (err) {
      return res.status(500).json({ message: "Database error" });
    }
    
    res.json(users);
  });
});

// Get all orders (admin only)
app.get("/api/admin/orders", verifyToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access required" });
  }

  db.all(`
    SELECT 
      o.id,
      o.total_amount,
      o.status,
      o.created_at,
      u.username,
      COUNT(oi.id) as item_count
    FROM orders o
    JOIN users u ON o.user_id = u.id
    LEFT JOIN order_items oi ON o.id = oi.order_id
    GROUP BY o.id
    ORDER BY o.created_at DESC
  `, [], (err, orders) => {
    if (err) {
      return res.status(500).json({ message: "Database error" });
    }
    
    res.json(orders);
  });
});

// ============= SERVE STATIC FILES =============
app.get("/admin.html", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/admin.html"));
});

app.get("/shop.html", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/shop.html"));
});

app.get("/login.html", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/login.html"));
});

app.get("/*", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/index.html"));
});

// ============= SERVER START =============
app.listen(PORT, () => {
  console.log(`🚀 FitGaleria Server Running on http://localhost:${PORT}`);
  console.log(`📊 Database: ${DB_PATH}`);
  console.log(`👤 Test Credentials:`);
  console.log(`   Admin: fitadmin / 1234`);
  console.log(`   User:  rimon / abcd`);
  console.log(`🔧 Features: Authentication, Products, Cart, Orders, Admin Dashboard, Wishlist`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🔄 Shutting down server...');
  db.close((err) => {
    if (err) {
      console.error('❌ Error closing database:', err.message);
    } else {
      console.log('✅ Database connection closed');
    }
    process.exit(0);
  });
});