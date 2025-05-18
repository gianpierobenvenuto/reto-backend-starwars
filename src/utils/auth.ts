/**
 * @file auth.ts
 * @description Utilidad para verificar tokens JWT en eventos de API Gateway.
 *              Valida el token usando una clave secreta definida por el entorno (JWT_SECRET).
 *              Devuelve un objeto que indica si la verificación fue exitosa y, en caso afirmativo, el payload decodificado.
 * @author Gianpiero Benvenuto
 */

import { APIGatewayProxyEvent } from "aws-lambda";
import jwt from "jsonwebtoken";

// Clave secreta para verificar el JWT (proporcionada por variable de entorno)
const SECRET_KEY = process.env.JWT_SECRET;

/**
 * Verifica el token JWT recibido en el encabezado de autorización de un evento de API Gateway.
 * Devuelve un objeto indicando si es válido, el payload decodificado o un mensaje de error.
 *
 * @param event Evento de API Gateway con encabezados HTTP
 * @returns Objeto con campos `valid`, `payload` (opcional) y `error` (opcional)
 */
export function verifyToken(event: APIGatewayProxyEvent): {
  valid: boolean;
  payload?: any;
  error?: string;
} {
  // Verificar que se haya configurado la clave secreta en el entorno
  if (!SECRET_KEY) {
    return {
      valid: false,
      error:
        "Configuración incorrecta del servidor: JWT_SECRET no está definido",
    };
  }

  // Obtener encabezado de autorización (case-insensitive)
  const authHeader =
    event.headers?.Authorization || event.headers?.authorization;

  if (!authHeader) {
    return { valid: false, error: "Encabezado de autorización ausente" };
  }

  // Separar el token del esquema Bearer
  const token = authHeader.split(" ")[1];
  if (!token) {
    return {
      valid: false,
      error: "Token ausente en el encabezado de autorización",
    };
  }

  // Verificar el token
  try {
    const payload = jwt.verify(token, SECRET_KEY);
    return { valid: true, payload };
  } catch (err) {
    return { valid: false, error: "Token inválido" };
  }
}
