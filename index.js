import express from "express";
import bodyParser from "body-parser"
import pg from "pg"
import bcrypt from "bcrypt";

const app = express();
const port = 3000;
const saltRounds = 10;

const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "users",
    password: "mydatabase",
    port: 5432,
});

db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
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
                    const result = await db.query(
                        "INSERT INTO users_cred (email,password) VALUES ($1, $2)",
                        [email, hash]
                    );
                    console.log(result);
                    res.render("profile.ejs");
                }
            });
        }
    } catch (err) {
        console.log(err);
    }
});

app.post("/login", async (req, res) => {
    const email = req.body.username;
    const loginPassword = req.body.password;

    try {
        const result = await db.query(
            "SELECT * FROM users_cred WHERE email= $1",
            [email]
        );

        if (result.rows.length > 0) {
            const user = result.rows[0];
            const storedHashedPassword = user.password;

            bcrypt.compare(loginPassword, storedHashedPassword, (err, result)=>{
                if(err){
                    console.log("Error comparing passwords:",err);
                }
                else{
                    if(result){//if true
                        res.render("profile.ejs");
                    }
                    else{
                        res.send("Incorrect password");
                    }
                }
            });
        }
        else {
            res.send("user not found.");
        }
    } catch (err) {
        console.log(err);
    }
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});