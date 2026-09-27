require("dotenv").config();

const express = require("express");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET;
const USERS_FILE = path.join(__dirname, "users.json");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Fix: Serve static files directly from root since HTML files are there
app.use(express.static(__dirname));

// Read users from JSON
function getUsers() {
    if (!fs.existsSync(USERS_FILE)) {
        fs.writeFileSync(USERS_FILE, "[]");
    }

    return JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
}

// Save users to JSON
function saveUsers(users) {
    fs.writeFileSync(
        USERS_FILE,
        JSON.stringify(users, null, 2)
    );
}

// ================= ROOT ROUTE =================

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

// ================= REGISTER =================

app.post("/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                message: "All fields are required"
            });
        }

        const users = getUsers();

        // Check existing email
        const existingUser = users.find(
            user => user.email === email
        );

        if (existingUser) {
            return res.status(400).json({
                message: "Email already registered"
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = {
            id: Date.now(),
            name,
            email,
            password: hashedPassword
        };

        users.push(newUser);

        saveUsers(users);

        res.json({
            message: "Registration successful"
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: "Server error"
        });
    }
});

// ================= LOGIN =================

app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const users = getUsers();

        const user = users.find(
            user => user.email === email
        );

        if (!user) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        const passwordMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatch) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        // Create JWT
        const token = jwt.sign(
            {
                id: user.id,
                email: user.email
            },
            SECRET_KEY,
            {
                expiresIn: "1h"
            }
        );

        res.json({
            message: "Login successful",
            token
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: "Server error"
        });
    }
});

// ================= AUTH MIDDLEWARE =================

function authenticateToken(req, res, next) {

    const authHeader = req.headers["authorization"];

    const token = authHeader &&
        authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            message: "Access denied"
        });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {

        if (err) {
            return res.status(403).json({
                message: "Invalid or expired token"
            });
        }

        req.user = user;

        next();
    });
}

// ================= HOME API =================

app.get("/api/home", authenticateToken, (req, res) => {

    const users = getUsers();

    const user = users.find(
        user => user.id === req.user.id
    );

    res.json({
        message: `Welcome ${user.name}!`,
        user: {
            name: user.name,
            email: user.email
        }
    });
});

// ================= SERVER =================

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});