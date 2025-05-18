/**
 * @file generate-token.js
 * @description Genera un token JWT para autenticación utilizando una clave secreta cargada desde el archivo .env.
 * @author Gianpiero Benvenuto
 */

require("dotenv").config(); // Cargar las variables de entorno desde el archivo .env

const jwt = require("jsonwebtoken");

// Obtener la clave secreta para firmar el token desde las variables de entorno
const SECRET_KEY = process.env.JWT_SECRET;

/**
 * Payload del token JWT.
 * @type {Object}
 * @property {string} userId - El identificador del usuario.
 * @property {string} role - El rol del usuario (por ejemplo, "admin").
 */
const payload = {
  userId: "test-user", // ID del usuario
  role: "admin", // Rol del usuario
};

/**
 * Generación del token JWT utilizando la clave secreta y el payload.
 * El token será utilizado para autenticar al usuario en las rutas protegidas.
 * @function
 * @returns {string} - El token JWT generado.
 */
const token = jwt.sign(payload, SECRET_KEY);

// Mostrar el token generado en la consola para su uso posterior
console.log("JWT Token:", token);
