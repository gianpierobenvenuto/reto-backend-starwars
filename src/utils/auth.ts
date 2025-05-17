import { APIGatewayProxyEvent } from "aws-lambda";
import jwt from "jsonwebtoken";

const SECRET_KEY = process.env.JWT_SECRET;

export function verifyToken(event: APIGatewayProxyEvent): {
  valid: boolean;
  payload?: any;
  error?: string;
} {
  if (!SECRET_KEY) {
    return {
      valid: false,
      error: "Server misconfiguration: JWT_SECRET is undefined",
    };
  }

  const authHeader =
    event.headers?.Authorization || event.headers?.authorization;

  if (!authHeader) {
    return { valid: false, error: "Authorization header missing" };
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return { valid: false, error: "Token missing" };
  }

  try {
    const payload = jwt.verify(token, SECRET_KEY);
    return { valid: true, payload };
  } catch (err) {
    return { valid: false, error: "Invalid token" };
  }
}
