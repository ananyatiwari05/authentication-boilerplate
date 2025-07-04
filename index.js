import express from "express";
import bodyParser from "body-parser"
import pg from "pg"
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});

db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 5,
    },
}));

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

app.get("/logout", (req, res, next) => {
    req.logout(function (err) {
        if (err) {
            return next(err);
        }
        res.redirect("/");
    });
});

app.get("/profile", async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const result = await db.query(
                `SELECT github, linkedin, leetcode, codechef FROM users_cred WHERE email = $1`,
                [req.user.email]
            );
            const user = result.rows[0];
            res.render("profile.ejs", {
                github: user.github || null,
                linkedin: user.linkedin || null,
                leetcode: user.leetcode || null,
                codechef: user.codechef || null,
                codeforces: user.codeforces || null
            });
        } catch (err) {
            console.error(err);
            res.send("Error loading profile");
        }
    } else {
        res.redirect("/login");
    }
});

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("profile.ejs");
    } else {
        res.redirect("/login");
    }
});

app.get("/auth/google", passport.authenticate("google", {
    scope: ["profile", "email"],
}));

app.get("/auth/google/userscred",
    passport.authenticate("google", {
        successRedirect: "/profile",
        failureRedirect: "/login",
    })
);

app.post("/register", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;

    try {
        const checkResult = await db.query("SELECT * FROM users_cred WHERE email= $1", [email]);

        if (checkResult.rows.length > 0) {
            res.redirect("/login");
        } else {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.log("Error hashing password:", err);
                } else {
                    const result = await db.query(
                        "INSERT INTO users_cred (email, password) VALUES ($1, $2) RETURNING *",
                        [email, hash]
                    );
                    const user = result.rows[0];
                    req.login(user, (err) => {
                        if (err) console.log(err);
                        res.redirect("/profile");
                    });
                }
            });
        }
    } catch (err) {
        console.log(err);
    }
});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/profile",
    failureRedirect: "/login"
}));

app.post("/submit", async (req, res) => {
    const { github, linkedin, leetcode, codechef } = req.body;
    try {
        await db.query(
            `UPDATE users_cred SET github = $1, linkedin = $2, leetcode = $3, codechef = $4 WHERE email = $5`,
            [github, linkedin, leetcode, codechef, req.user.email]
        );
        res.redirect("/profile");
    } catch (err) {
        console.log(err);
        res.send("Failed to update profile");
    }
});

passport.use(new Strategy(async function verify(username, password, cb) {
    try {
        const result = await db.query("SELECT * FROM users_cred WHERE email= $1", [username]);

        if (result.rows.length > 0) {
            const user = result.rows[0];
            const storedHashedPassword = user.password;

            bcrypt.compare(password, storedHashedPassword, (err, result) => {
                if (err) return cb(err);
                if (result) return cb(null, user);
                return cb(null, false);
            });
        } else {
            return cb("User not found");
        }
    } catch (err) {
        return cb(err);
    }
}));

passport.use("google", new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/userscred",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
}, async (accessToken, refreshToken, profile, cb) => {
    try {
        const result = await db.query("SELECT * FROM users_cred WHERE email = $1", [profile.email]);

        if (result.rows.length === 0) {
            const newUser = await db.query(
                "INSERT INTO users_cred (email, password) VALUES ($1, $2)",
                [profile.email, "google"]
            );
            return cb(null, newUser.rows[0]);
        } else {
            return cb(null, result.rows[0]);
        }
    } catch (err) {
        return cb(err);
    }
}));

passport.serializeUser((user, cb) => {
    cb(null, user);
});

passport.deserializeUser((user, cb) => {
    cb(null, user);
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
