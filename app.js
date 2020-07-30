//jshint esversion:6

const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost:27017/secretsDB', {useNewUrlParser: true, useUnifiedTopology: true});

const app = express();

app.use(express.static("public"));
app.set('view engine', "ejs");
app.use(bodyParser.urlencoded({
  extended: true
}));

const userSchema = {
  email: String,
  password: String
}

// mongoose db model

const User = mongoose.model("User", userSchema);


app.get("/", function(req, res){
  res.render("home");
});

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.post("/register", function(req, res){
  const newUser = new User({
    email: req.body.username,
    password: req.body.password
  });
  newUser.save(function(err){
    if(!err){
      res.render("secrets");
    } else {
      console.log(err);
    }
  });
});

app.post("/login", function(req, res){
  User.findOne(
    {email: req.body.username,
    password: req.body.password},
    function(err, result){
      if (!err){
        if (result) {
          res.render("secrets");
        } else {
          console.log("Sorry no users matched that criteria");
          res.render("login")
        }
      } else {
        console.log(err);
        res.render("login");
      }
  });
});



app.listen(3000, function(){
  console.log("Server started on port 3000");
});
