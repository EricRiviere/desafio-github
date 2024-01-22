import passport from "passport";
import passportLocal from "passport-local";
import GitHubStrategy from "passport-github2";
import userModel from "../dao/models/user.model.js";
import { createHash, isValidPassword } from "../utils.js";
import dotenv from "dotenv";
dotenv.config();

//Local Strategy
const localStrategy = passportLocal.Strategy;

const initializePassport = () => {
  //Github register
  passport.use(
    "github",
    new GitHubStrategy(
      {
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackUrl: process.env.GITHUB_CALLBACK_URL,
      },
      async (accessToken, refreshToken, profile, done) => {
        console.log("Profile obtenido del usuario de GitHub: ");
        console.log(profile);
        try {
          //Validamos si el user existe en la DB
          const user = await userModel.findOne({ email: profile._json.email });
          console.log("User found for login:");
          console.log(user);
          if (!user) {
            console.warn(
              "User doesn't exists with email: " + profile._json.email
            );
            let newUser = {
              first_name: profile._json.name,
              last_name: "",
              age: 18,
              email: profile._json.email,
              password: "",
              loggedBy: "GitHub",
              rol: "user",
            };
            const result = await userModel.create(newUser);
            return done(null, result);
          } else {
            // Si entramos por aca significa que el user ya existe en la DB
            return done(null, user);
          }
        } catch (error) {
          return done(error);
        }
      }
    )
  );
  //Passport Local
  //Register
  passport.use(
    "register",
    new localStrategy(
      { passReqToCallback: true, usernameField: "email" },
      async (req, username, password, done) => {
        const { first_name, last_name, email, age } = req.body;
        try {
          const user = await userModel.findOne({ email });
          if (user) {
            console.log("User registered with provided email");
            done(null, false);
          }
          let role;
          if (email === "adminCoder@coder.com") {
            role = "admin";
          }
          const newUser = {
            first_name,
            last_name,
            email,
            age,
            password: createHash(password),
            loggedBy: "App",
            role,
          };
          const result = await userModel.create(newUser);
          return done(null, result);
        } catch (error) {
          return done("Error registering user: " + error);
        }
      }
    )
  );

  //Login
  passport.use(
    "login",
    new localStrategy(
      { passReqToCallback: true, usernameField: "email" },
      async (req, username, password, done) => {
        try {
          const user = await userModel.findOne({ email: username });
          console.log("User found for login:");
          console.log(user);
          if (!user) {
            console.warn("No user registered with email: " + username);
            return done(null, false);
          }
          if (!isValidPassword(user, password)) {
            console.warn("Invalid credentials");
            return done(null, false);
          }
          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );

  //Serialize function
  passport.serializeUser((user, done) => {
    done(null, user._id);
  });
  //Deserialize function
  passport.deserializeUser(async (id, done) => {
    try {
      let user = await userModel.findById(id);
      done(null, user);
    } catch (error) {
      console.error("Error deserializing user: " + error);
    }
  });
};

export default initializePassport;
