const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = 3000;

// Set up database
const db = new sqlite3.Database(':memory:');

// Create users table
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)");
});

// Middleware
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'secretkey',
  resave: false,
  saveUninitialized: false
}));

// Routes
app.get('/', (req, res) => {
  res.render('login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  // Insert user into the database
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], function(err) {
    if (err) {
      return res.status(500).send("User already exists");
    }
    res.redirect('/');
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Retrieve user from database
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err || !user) {
      return res.status(400).send('Cannot find user');
    }

    try {
      if (await bcrypt.compare(password, user.password)) {
        req.session.userId = user.id;
        res.redirect('/dashboard');
      } else {
        res.send('Not Allowed');
      }
    } catch {
      res.status(500).send();
    }
  });
});

app.get('/dashboard', (req, res) => {
  if (req.session.userId) {
    res.render('dashboard');
  } else {
    res.redirect('/');
  }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
      if (err) {
        return res.redirect('/dashboard');
      }
      res.clearCookie('connect.sid');
      res.redirect('/');
    });
  });
  

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
