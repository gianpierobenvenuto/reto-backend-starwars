/**
 * @file historial.ts
 * @description Lambda handler para el endpoint GET /historial.
 *              Recupera registros almacenados previamente desde DynamoDB con paginación y orden cronológico inverso (más recientes primero).
 *              Valida parámetros de consulta, verifica JWT y estructura la respuesta adecuadamente.
 * @author Gianpiero Benvenuto
 */

import { APIGatewayProxyHandler } from "aws-lambda";
import { DynamoDBClient, ScanCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { z, ZodError } from "zod";
import { verifyToken } from "../utils/auth";

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
export const handler: APIGatewayProxyHandler = async (event) => {
  // Verificar token JWT
  const auth = verifyToken(event);
  if (!auth.valid) {
    return {
      statusCode: 401,
      body: JSON.stringify({ error: auth.error }),
    };
  }

  try {
    // Validar y extraer parámetros de consulta
    const query = querySchema.parse(event.queryStringParameters || {});
    const limit = query.limit ?? 10;

    // Si se incluye un lastKey (paginación), decodificarlo
    const lastKey = query.lastKey
      ? JSON.parse(decodeURIComponent(query.lastKey))
      : undefined;

    // Construir parámetros de escaneo en DynamoDB
    const params: any = {
      TableName: TABLE_NAME,
      Limit: limit,
    };

    if (lastKey) {
      params.ExclusiveStartKey = lastKey;
    }

    // Ejecutar escaneo
    const command = new ScanCommand(params);
    const response = await client.send(command);

    // Transformar resultados desde formato DynamoDB a objetos JS
    const items = response.Items
      ? response.Items.map((item) => unmarshall(item))
      : [];

    // Ordenar los resultados por timestamp descendente (más recientes primero)
    items.sort((a, b) => b.timestamp - a.timestamp);

    return {
      statusCode: 200,
      body: JSON.stringify({
        items,
        // Enviar nueva lastKey para la siguiente página si existe
        lastKey: response.LastEvaluatedKey
          ? encodeURIComponent(JSON.stringify(response.LastEvaluatedKey))
          : null,
      }),
    };
  } catch (error: any) {
    if (error instanceof ZodError) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          error: error.errors.map((e) => e.message).join(", "),
        }),
      };
    }
    return {
      statusCode: 500,
      body: JSON.stringify({ error: error.message }),
    };
  }
};
