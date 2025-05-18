const jwt = require("jsonwebtoken");

const SECRET_KEY = "reto_backend_starwars_rimac_1234567890";

const payload = {
  userId: "test-user",
  role: "admin",
};

const token = jwt.sign(payload, SECRET_KEY);

console.log("JWT Token:", token);
