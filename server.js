require('dotenv').config()
var express = require('express');
var app = express();
var bodyParser = require('body-parser')
const microserviceRoutes = require('./CalMicroService');
const bcrypt = require('bcrypt')
const passport = require('passport')
const flash = require('express-flash')
const session = require('express-session')
const jwt = require('jsonwebtoken')
const JWTstrategy = require("passport-jwt").Strategy;
const fakeLocal = require("./fakeLocal.json");

app.use(express.static(__dirname))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: false}))
app.use('/api', microserviceRoutes)
app.use(express.json());
app.set("view engine", "ejs");
app.use(flash())
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  }))
app.use(passport.session()) 
const initializePassport = require('./passport-config') 
initializePassport(
  passport,
  email => users.find(user => user.email === email),
  id => users.find(user => user.id === id)
)

app.use(passport.initialize())

function getJwt() {
    console.log("in getJwt");
    return fakeLocal.Authorization?.substring(7); // remove the "Bearer " from the token.
}

passport.use(
    new JWTstrategy(
      {
        secretOrKey: "TOP_SECRET",
        jwtFromRequest: getJwt,
      },
      async (token, done) => {
        console.log("in jwt strat. token: ", token);

        if (token?.user?.email == "tokenerror") {
          let testError = new Error(
            "something bad happened. we've simulated an application error in the JWTstrategy callback for users with an email of 'tokenerror'."
          );
          return done(testError, false);
        }
  
        if (token?.user?.email == "emptytoken") {
          return done(null, false); // unauthorized
        }
        // 3. Successfully decoded and validated user:
        return done(null, token.user);
      }
    )
  );

const users = []

app.get('/', checkAuthenticated, (req, res) => {
    res.render('index.ejs', { name: req.user.name })
  })

  app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs')
  })
  app.post('/register', checkNotAuthenticated, async (req, res) => {
    try {
      const hashedPassword = await bcrypt.hash(req.body.password, 10)
      users.push({
        id: Date.now().toString(),
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword
      })
      res.redirect('/login')
    } catch {
      res.redirect('/register')
    }
  })
app.get('/login', checkNotAuthenticated, (req, res) => {
  res.render('login.ejs')
})
app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/calculator',
    failureRedirect: '/login',
    failureFlash: true
}))
app.get('/calculator',checkAuthenticated,(req,res)=> { 
    res.render('index');
});
app.post('/getResult',passport.authenticate("jwt",{session: false}),(req,res) => {
    let operation = req.query.op;
    res.send(operation);
});

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) { 
      return next()
    }
    res.redirect('/login')
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/calculator')
    }
    next()
}

var server = app.listen(3000,() => {
    console.log('server is listening on port', server.address().port);
});