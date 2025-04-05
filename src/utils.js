import { fileURLToPath } from "url";
import { dirname } from "path";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import passport from "passport";
import { log } from "console";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

//bCrypt
export const createHash = (password) =>
  bcrypt.hashSync(password, bcrypt.genSaltSync(10));
export const isValidPassword = (user, password) => {
  console.log(
    `Datos a validar: user-password: ${user.password}, password: ${password}`
  );
  return bcrypt.compareSync(password, user.password);
};

//JSON Web Tokens JWT functinos:
export const PRIVATE_KEY = "CoderKeySecretJWT";
//Generate token JWT usando jwt.sign:
export const generateJWToken = (user) => {
  return jwt.sign({ user }, PRIVATE_KEY, { expiresIn: "24h" });
};

//Autenticar token JWT (middleware).

export const authToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  console.log("Token present in header auth:");
  console.log(authHeader);
  if (!authHeader) {
    return res
      .status(401)
      .send({ error: "User not authenticated or missing token." });
  }
  const token = authHeader.split(" ")[1]; //Split para retirar "Bearer".
  jwt.verify(token, PRIVATE_KEY, (error, credentials) => {
    if (error)
      return res.status(403).send({ error: "Token invalid, Unauthorized!" });
    req.user = credentials.user;
    console.log(req.user);
    next();
  });
};

export const passportCall = (strategy) => {
  return async (req, res, next) => {
    passport.authenticate(strategy, function (err, user, info) {
      if (err) return next(err);
      if (!user) {
        return res
          .status(401)
          .send({ error: info.messages ? info.messages : info.toString() });
      }

      req.user = user;

      next();
    })(req, res, next);
  };
};

export const cookieExtractor = (req) => {
  let token = null;
  console.log("CookieExtractor");
  console.log(req);

  if (req && req.cookies) {
    console.log("Cookies presentes: ");
    console.log(req.cookies);
    token = req.cookies["jwtCookieToken"];

    console.log("Token obtenido desde Cookie:");
    console.log(token);
  }

  return token;
};

export const authorization = (role) => {
  return async (req, res, next) => {
    if (!req.user)
      return res.status(401).send("Unauthorized: User not found in JWT");

    if (req.user.role !== role) {
      return res
        .status(403)
        .send("Forbidden: El usuario no tiene permisos con este rol.");
    }

    next();
  };
};

export default __dirname;
