/**
 * @file auth.ts
 * @description Utilidad para verificar tokens JWT en eventos de API Gateway.
 *              Valida el token usando una clave secreta definida por el entorno (JWT_SECRET).
 *              Devuelve un objeto que indica si la verificación fue exitosa y, en caso afirmativo, el payload decodificado.
 * @author Gianpiero Benvenuto
 */

import { APIGatewayProxyEvent } from "aws-lambda";
import jwt from "jsonwebtoken";
import { logToCloudWatch } from "../utils/cloudwatchLogger"; // Importa el logger

// Clave secreta para verificar el JWT (proporcionada por variable de entorno)
const SECRET_KEY = process.env.JWT_SECRET;

/**
 * Verifica el token JWT recibido en el encabezado de autorización de un evento de API Gateway.
 * Devuelve un objeto indicando si es válido, el payload decodificado o un mensaje de error.
 *
 * @param event Evento de API Gateway con encabezados HTTP
 * @returns Objeto con campos `valid`, `payload` (opcional) y `error` (opcional)
 */
export async function verifyToken(event: APIGatewayProxyEvent): Promise<{
  valid: boolean;
  payload?: any;
  error?: string;
}> {
  // Log de inicio de la verificación del token
  await logToCloudWatch("Verificando el token JWT recibido", "INFO");

  // Verificar que se haya configurado la clave secreta en el entorno
  if (!SECRET_KEY) {
    const errorMessage =
      "Configuración incorrecta del servidor: JWT_SECRET no está definido";
    await logToCloudWatch(errorMessage, "ERROR");
    return {
      valid: false,
      error: errorMessage,
    };
  }

  // Obtener encabezado de autorización (case-insensitive)
  const authHeader =
    event.headers?.Authorization || event.headers?.authorization;

  if (!authHeader) {
    const errorMessage = "Encabezado de autorización ausente";
    await logToCloudWatch(errorMessage, "ERROR");
    return { valid: false, error: errorMessage };
  }

  // Separar el token del esquema Bearer
  const token = authHeader.split(" ")[1];
  if (!token) {
    const errorMessage = "Token ausente en el encabezado de autorización";
    await logToCloudWatch(errorMessage, "ERROR");
    return {
      valid: false,
      error: errorMessage,
    };
  }

  // Verificar el token
  try {
    const payload = jwt.verify(token, SECRET_KEY);
    await logToCloudWatch("Token verificado con éxito", "INFO");
    return { valid: true, payload };
  } catch (err) {
    const errorMessage = "Token inválido";
    await logToCloudWatch(errorMessage, "ERROR");
    return { valid: false, error: errorMessage };
  }
}
