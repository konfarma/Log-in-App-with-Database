import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";
import GoogleStrategy from "passport-google-oauth2";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(session({
    secret:process.env.SESSION_SECRET,
    resave:false,
    saveUninitialized:true,
    cookie:{maxAge:1000*60*60}
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
  });
db.connect();

app.get("/", (req,res)=>{
    res.render("home.ejs");
});
app.get("/register",(req,res)=>{
    res.render("register.ejs");
});
app.get("/login",(req,res)=>{
    res.render("login.ejs");
});
app.get("/secrets",(req,res)=>{
    if(req.isAuthenticated()){
        const secret=req.user.secret;
        if(secret===null){
            res.redirect("/submit");
        }else{
            res.render("secrets.ejs",{secret:secret});
        }
        
    }else{
        res.redirect("/login");
    }
});
app.get("/submit",(req,res)=>{
    if(req.isAuthenticated()){
        res.render("submit.ejs");
      }else{
        res.redirect("/login");
    }
})
app.get("/auth/google",passport.authenticate("google",{
    scope:["profile","email"]
}));

app.get("/auth/google/secrets",passport.authenticate("google",{
    successRedirect:"/secrets",
    failureRedirect:"/login"
}));
app.get("/logout", (req, res) => {
    req.logout(function (err) {
      if (err) {
        return next(err);
      }
      res.redirect("/");
    });
  });

app.post("/register",async (req,res)=>{
    const username=req.body.username;
    const password= req.body.password;
    try {
        const checkUsers=await db.query("SELECT email from users WHERE email=$1",[username]);
        if(checkUsers.rows.length>0){
            res.redirect("/login")
        }else{
            bcrypt.hash(password,saltRounds,async(err,hash)=>{
                if(err){
                    console.error("Error hashing password:", err);
                }else{
                    const result= await db.query("INSERT INTO users (email,password) VALUES ($1,$2) RETURNING *",[username,hash]);
                    const user=result.rows[0];
                    req.login(user,(err)=>{
                        res.redirect("/secrets")
                    })
                }
            });
        }
        
    } catch (error) {
        console.log(error)
    }
    
});
app.post("/login",passport.authenticate("local",{
    successRedirect:"/secrets",
    failureRedirect:"/login"
}));
app.post("/submit",async (req,res)=>{
    const secret=req.body.secret;
    const result=await db.query("UPDATE users SET secret = $1 WHERE email=$2 RETURNING *",[secret,req.user.email]);
    req.user.secret = result.rows[0].secret;//instant secret update
    res.redirect("/secrets");
})

passport.use("local",new Strategy(async function verify(username,password,cb){
    try {
        const result=await db.query("SELECT * FROM users WHERE email=$1",[username]);
        if(result.rows.length>0){
            const user=result.rows[0];
            const hashedPassword=user.password;
            bcrypt.compare(password,hashedPassword,(err, result)=>{
                if(err){
                    return cb(err)
                }else{
                    if(result){
                        return cb(null,user)
                    }else{
                        return cb(null,false)
                    }
                }
            });
        }else{
            return cb("User does not exist");
        }
    } catch (err) {
        return cb(err)
    }
}));
passport.use("google",new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},async (accessToken,refreshToken,profile,cb)=>{
    try {
        const result=await db.query("SELECT * FROM users WHERE email=$1",[profile.email]);
        if(result.rows.length === 0){
            const newUser=await db.query("INSERT INTO users (email,password) VALUES ($1,$2)",[profile.email,"google"]);
            cb(null,newUser.rows[0])
        }else{
            //Already have the google user
            cb(null,result.rows[0])

        }
    } catch (error) {
        cb(error);
    }
}));
passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});