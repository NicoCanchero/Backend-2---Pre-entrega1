import passport from "passport";
import passportLocal from "passport-local";
import GitHubStrategy from "passport-github2";
import jwtStrategy from "passport-jwt";
import userModel from "../models/user.model.js";
import {
  createHash,
  isValidPassword,
  PRIVATE_KEY,
  cookieExtractor,
} from "../utils.js";

//Strategies:
const localStrategy = passportLocal.Strategy;
const JwtStrategy = jwtStrategy.Strategy;
const ExtractJWT = jwtStrategy.ExtractJwt;

const initializePassport = () => {
  /*JWT Strategy (para acceso con token en cookies)*/
  passport.use(
    "jwt",
    new JwtStrategy(
      {
        jwtFromRequest: ExtractJWT.fromExtractors([cookieExtractor]),
        secretOrKey: PRIVATE_KEY,
      },
      async (jwt_payload, done) => {
        console.log("Entrando a passport Strategy con JWT.");
        try {
          console.log("JWT obtenido del payload");
          console.log(jwt_payload);
          return done(null, jwt_payload.user);
        } catch (error) {
          console.error(error);
          return done(error);
        }
      }
    )
  );

  /*Strategy 'current': para obtener el usuario actual desde el JWT*/
  passport.use(
    "current",
    new JwtStrategy(
      {
        jwtFromRequest: ExtractJWT.fromExtractors([cookieExtractor]),
        secretOrKey: PRIVATE_KEY,
      },
      async (jwt_payload, done) => {
        try {
          return done(null, jwt_payload.user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );

  /*GitHub Strategy*/
  passport.use(
    "github",
    new GitHubStrategy(
      {
        clientID: "<your-clientID>",
        clientSecret: "<your-clienteSecret>",
        callbackUrl: "http://localhost:9090/api/sessions/githubcallback",
      },
      async (accessToken, refreshToken, profile, done) => {
        console.log("Profile obtenido del usuario: ");
        console.log(profile);
        try {
          const user = await userModel.findOne({ email: profile._json.email });
          console.log("Usuario encontrado para login:");
          console.log(user);
          if (!user) {
            console.warn(
              "User doesn't exists with username: " + profile._json.email
            );
            let newUser = {
              first_name: profile._json.name,
              last_name: "",
              age: 18,
              email: profile._json.email,
              password: "",
              loggedBy: "GitHub",
            };
            const result = await userModel.create(newUser);
            return done(null, result);
          } else {
            return done(null, user);
          }
        } catch (error) {
          return done(error);
        }
      }
    )
  );

  /*Register Strategy*/
  passport.use(
    "register",
    new localStrategy(
      { passReqToCallback: true, usernameField: "email" },
      async (req, email, password, done) => {
        const { first_name, last_name, age } = req.body;
        try {
          const exists = await userModel.findOne({ email });
          if (exists) {
            console.log("El usuario ya existe.");
            return done(null, false);
          }

          const user = {
            first_name,
            last_name,
            email,
            age,
            password: createHash(password),
            loggedBy: "App",
          };

          const result = await userModel.create(user);
          return done(null, result);
        } catch (error) {
          return done("Error registrando el usuario: " + error);
        }
      }
    )
  );

  /*Login Strategy*/
  passport.use(
    "login",
    new localStrategy(
      { passReqToCallback: true, usernameField: "email" },
      async (req, username, password, done) => {
        try {
          const user = await userModel.findOne({ email: username });
          console.log("Usuario encontrado para login:");
          console.log(user);
          if (!user) {
            console.warn("User doesn't exists with username: " + username);
            return done(null, false);
          }
          if (!isValidPassword(user, password)) {
            console.warn("Invalid credentials for user: " + username);
            return done(null, false);
          }
          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );

  /*Serialización y deserialización*/
  passport.serializeUser((user, done) => {
    done(null, user._id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      let user = await userModel.findById(id);
      done(null, user);
    } catch (error) {
      console.error("Error deserializando el usuario: " + error);
    }
  });
};

export default initializePassport;
