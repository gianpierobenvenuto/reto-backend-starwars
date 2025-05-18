/**
 * @file historial.ts
 * @description Lambda handler para el endpoint GET /historial.
 *              Recupera registros almacenados previamente desde DynamoDB con paginación y orden cronológico inverso (más recientes primero).
 *              Valida parámetros de consulta, verifica JWT y estructura la respuesta adecuadamente.
 * @author Gianpiero Benvenuto
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { DynamoDBClient, ScanCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { z, ZodError } from "zod";
import { verifyToken } from "../utils/auth";
import { logToCloudWatch } from "../utils/cloudwatchLogger";

// Nombre de la tabla a consultar
const TABLE_NAME = process.env.DYNAMO_TABLE!;
const client = new DynamoDBClient({});

// Esquema de validación para los parámetros de consulta: limit y lastKey
const querySchema = z.object({
  limit: z.preprocess((val) => {
    if (typeof val === "string" && /^\d+$/.test(val)) {
      return Number(val);
    }
    return val;
  }, z.number().int().positive().optional()),
  lastKey: z.string().optional(),
});

/**
 * Lambda principal para recuperar historial de planetas fusionados.
 * Aplica autenticación, validación de parámetros y paginación con LastEvaluatedKey.
 */
export const handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  // Log de la solicitud entrante
  await logToCloudWatch(`Ruta solicitada: ${event.path}`, "INFO");

  // Verificar token JWT
  const auth = await verifyToken(event);
  if (!auth.valid) {
    await logToCloudWatch(`Autenticación fallida: ${auth.error}`, "ERROR");
    return {
      statusCode: 401,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: auth.error }),
    };
  }

  try {
    // Validar y extraer parámetros de consulta
    const query = querySchema.parse(event.queryStringParameters || {});
    const limit = query.limit ?? 10;
    const lastKey = query.lastKey
      ? JSON.parse(decodeURIComponent(query.lastKey))
      : undefined;

    await logToCloudWatch(
      `Parámetros de consulta validados: limit=${limit}, lastKey=${query.lastKey}`,
      "INFO"
    );

    // Construir parámetros de escaneo en DynamoDB
    const params: any = {
      TableName: TABLE_NAME,
      Limit: limit,
    };
    if (lastKey) params.ExclusiveStartKey = lastKey;

    // Ejecutar escaneo
    const dbResponse = await client.send(new ScanCommand(params));
    const items = (dbResponse.Items ?? []).map((i) => unmarshall(i));
    items.sort((a, b) => b.timestamp - a.timestamp);

    await logToCloudWatch(
      `Enviando respuesta con ${items.length} items`,
      "INFO"
    );

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        items,
        lastKey: dbResponse.LastEvaluatedKey
          ? encodeURIComponent(JSON.stringify(dbResponse.LastEvaluatedKey))
          : null,
      }),
    };
  } catch (error: unknown) {
    if (error instanceof ZodError) {
      const msg = error.errors.map((e) => e.message).join(", ");
      await logToCloudWatch(`Errores de validación: ${msg}`, "ERROR");
      return {
        statusCode: 400,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: msg }),
      };
    }

    const message =
      error instanceof Error ? error.message : "Error desconocido";
    await logToCloudWatch(`Error interno del servidor: ${message}`, "ERROR");
    return {
      statusCode: 500,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: message }),
    };
  }
};
