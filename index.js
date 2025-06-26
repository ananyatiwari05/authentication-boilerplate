import express from "express";
import bodyParser from "body-parser"
import pg from "pg"
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABSE,
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
    cookie:{
        //the time span of a cookie
        //by default the cookie expires as we close our browser
        //currently set to 5 hours
        maxAge: 1000 * 60 * 60 * 5,
    },
}));

//passport session after session initialization

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

app.get("/profile", (req,res)=>{
    //if we have an active session saved in a cookie
    //then we can directly show the profile page
    //instead of repeated logins

    if(req.isAuthenticated()){
        res.render("profile.ejs");
    }
    else{
        res.redirect("/login");
    }
});

app.post("/register", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;

    try {
        //if the user already registered
        const checkResult = await db.query(
            "SELECT * FROM users_cred WHERE email= $1",
            [email]
        );

        if (checkResult.rows.length > 0) {
            res.send("Email already exists. Try logging in.");
        }
        else {
            //pasword hashing
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.log("Error hashing password:", err);
                }
                else {
                    //getting hold of the credetials entered by the user while registering
                    const result = await db.query(
                        "INSERT INTO users_cred (email,password) VALUES ($1, $2) RETURNING *",
                        [email, hash]
                    );
                    const user= result.rows[0];
                    //req.login() automatically authenticates our user
                    req.login(user, (err)=>{
                        console.log(err);
                        res.redirect("/profile");
                    });
                }
            });
        }
    } catch (err) {
        console.log(err);
    }
});

//instead of manual checking we now as passport pkg to do that work for us
//the strategy used is local
app.post("/login", passport.authenticate("local", {
    successRedirect:"/profile",
    failureRedirect:"/login"
}));


passport.use(new Strategy(async function verify(username, password, cb){
    //passwort will automatically grap the username and password
    //from the login and register routes
    //and we dont have to manually do it using body-parser
    
    try {
        const result = await db.query(
            "SELECT * FROM users_cred WHERE email= $1",
            [username],
        );

        if (result.rows.length > 0) {
            const user = result.rows[0];
            const storedHashedPassword = user.password;

            bcrypt.compare(password, storedHashedPassword, (err, result)=>{
                if(err){
                    return cb(err);
                }
                else{
                    if(result){//if true
                        return cb(null, user);
                        //(error, value)
                        //in app.get("/profile")=> it will be set true as user value is passed and profile page will show up
                    }
                    else{
                        return cb(null, false);
                        //in app.get("/profile")=> it will be set to false and profile page will nt show up
                    }
                }
            });
        }
        else {
            return cb("User not found");
        }
    } catch (err) {
        return cb(err);
    }
}));
//cb-> callback in passport world

//saving the data of the user who logged in inside the local storage
passport.serializeUser((user, cb) =>{
    cb(null, user);
});

passport.deserializeUser((user, cb) =>{
    cb(null, user);
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});