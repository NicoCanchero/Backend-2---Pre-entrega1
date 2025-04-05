import { Router } from "express";
import passport from "passport";
import userModel from "../models/user.model.js";
import { isValidPassword, generateJWToken } from "../utils.js";

const router = Router();

router.get(
  "/github",
  passport.authenticate("github", { scope: ["user:email"] }),
  async (req, res) => {}
);

router.get(
  "/githubcallback",
  passport.authenticate("github", { failureRedirect: "/github/error" }),
  async (req, res) => {
    const user = req.user;
    req.session.user = {
      name: `${user.first_name} ${user.last_name}`,
      email: user.email,
      age: user.age,
    };
    req.session.admin = true;
    //res.redirect("/users");
    res.redirect("/api/sessions/current");
  }
);

// Ruta con estrategia "current"
router.get(
  "/current",
  passport.authenticate("current", { session: false }),
  async (req, res) => {
    res.send({
      status: "success",
      message: "Usuario autenticado con JWT",
      payload: req.user,
    });
  }
);

router.post(
  "/register",
  passport.authenticate("register", {
    failureRedirect: "/api/sessions/fail-register",
  }),
  async (req, res) => {
    console.log("Registrando nuevo usuario.");
    res
      .status(201)
      .send({ status: "success", message: "Usuario creado con extito." });
  }
);

router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await userModel.findOne({ email: email });
    if (!user)
      return res.status(401).json({ message: "Usuario no encontrado" });

    if (!isValidPassword(user, password)) {
      console.warn("Invalid credentials for user: " + email);
      return res
        .status(401)
        .send({ status: "error", error: "Credenciales invalidas!!!" });
    }

    // Generar un Obj para el JWT - DTO (no agregamos data sensible)
    const tokenUser = {
      name: `${user.first_name} ${user.last_name}`,
      email: user.email,
      age: user.age,
      role: user.role,
    };

    // Generamos el JWT
    const access_token = generateJWToken(tokenUser);
    console.log("access_token", access_token);

    // Cookie con el token
    res.cookie("jwtCookieToken", access_token, {
      maxAge: 600000,
      httpOnly: true,
    });

    //res.send({ message: "Login successfull" });
    res.redirect("/api/sessions/current");
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .send({ status: "error", error: "Error interno de la aplicación." });
  }
});

router.get("/fail-register", (req, res) => {
  res.status(401).send({ error: "Failed to process register!" });
});

router.get("/fail-login", (req, res) => {
  res.status(401).send({ error: "Failed to process login!" });
});

export default router;
