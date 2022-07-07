
require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();



app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: "this is our little secret",
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userdata", { useNewUrlParser: true });


const userDataschema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userDataschema.plugin(passportLocalMongoose);
userDataschema.plugin(findOrCreate);



const user = new mongoose.model("user", userDataschema);

passport.use(user.createStrategy());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    user.findById(id, function (err, user) {
        done(err, user);
    });
});


passport.use(new GoogleStrategy({
    clientID: process.env.client_id,
    clientSecret: process.env.client_secret,
    callbackURL: "http://www.example.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        user.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", function (req, res) {
    res.render("home");
})

app.get("/auth/google",
    passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: "/login" }),
    function (req, res) {
        // Successful authentication, redirect to secrets.
        res.redirect("/secrets");
    });

app.get("/login", function (req, res) {
    res.render("login");
})
app.get("/register", function (req, res) {
    res.render("register");
})

app.get("/secrets", function (req, res) {
    
    user.find({secret:{$ne:null}} , function(err , foundUsers){
        if(err){
            console.log(err);
        }else{
            if(foundUsers){
                res.render("secrets" , {userWithSecrects : foundUsers});
            }
        }
    })
})

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit" , function(req , res){
    const secretEntered = req.body.secret;

    user.findById(req.user.id , function(err , foundUser){
        if(err){
            console.log(err);
        }
        else{
            if(foundUser){
                foundUser.secret = secretEntered;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    });
});

app.get("/logout", function (req, res) {
    req.logOut();
    res.redirect("/");
})

app.post("/register", function (req, res) {

    user.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        }
        else {
            passport.authenticate("local")(req, res, function () {

                res.redirect("/secrets");
            })
        }
    })

});

app.post("/login", function (req, res) {

    const user1 = new user({
        username: req.body.username,
        password: req.body.password
    })

    req.logIn(user1, function (err, result) {
        if (err) {
            console.log(err);
        }
        else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            })
        }
    })
})





app.listen("3000", function () {
    console.log("server running in port 3000 ");
})


