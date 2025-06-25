import express from "express";
import bodyParser from "body-parser"
import pg from "pg"

const db= new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "auth",
    password: "mydatabse",
    port: 5432,
});

const app = express();
const port = 3000;

db.connect();


app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req,res)=>{
    res.render("home.ejs");
});

app.get("/login", (req,res)=>{
    res.render("login.ejs");
});

app.get("/register", (req,res)=>{
    res.render("register.ejs");
});

app.post("/register", async (req,res)=>{
    const email=req.body.username;
    const password= req.body.password;
});

app.post("/rlogin", async (req,res)=>{
    const email=req.body.username;
    const password= req.body.password;
});

app.listen(port, ()=>{
    console.log(`Server is running on port ${port}`);
});