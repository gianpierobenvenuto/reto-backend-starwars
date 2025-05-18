/**
 * @file almacenar.ts
 * @description Lambda handler para almacenar planetas personalizados en DynamoDB. Incluye autenticación JWT, validación de entrada con Zod,
 *              y consulta de clima mediante coordenadas.
 * @author Gianpiero Benvenuto
 */

import { APIGatewayProxyHandler } from "aws-lambda";
import { z, ZodError } from "zod";
import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { verifyToken } from "../utils/auth";
import { getCoordinates } from "../services/geoService";
import { getWeatherByLatLon } from "../services/weatherService";

// Nombre de la tabla DynamoDB tomada de las variables de entorno
const TABLE_NAME = process.env.DYNAMO_TABLE!;

// Cliente de DynamoDB
const client = new DynamoDBClient({});

// Esquema de validación para el cuerpo de la petición utilizando Zod,
// usando `required_error` para generar mensajes cuando el campo está ausente.
const bodySchema = z.object({
  id: z
    .string({ required_error: 'El campo "id" es obligatorio' })
    .min(1, 'El campo "id" es obligatorio'),
  planetName: z.string({
    required_error: 'El campo "planetName" es obligatorio',
  }),
  climate: z.string({
    required_error: 'El campo "climate" es obligatorio',
  }),
  population: z.string().optional(),
});

/**
 * Lambda handler para el endpoint POST /almacenar.
 * Verifica el token JWT, valida el payload, obtiene clima por coordenadas, y almacena el resultado en DynamoDB.
 */
export const handler: APIGatewayProxyHandler = async (event) => {
  // Verificar autenticación JWT
  const auth = verifyToken(event);
  if (!auth.valid) {
    return {
      statusCode: 401,
      body: JSON.stringify({ error: auth.error }),
    };
  }

  try {
    // Validar existencia del cuerpo
    if (!event.body) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          error: "No se proporcionó cuerpo en la petición",
        }),
      };
    }

    // Parsear y validar el body con Zod
    const data = JSON.parse(event.body);
    const parsed = bodySchema.parse(data);

    // Obtener coordenadas del planeta para luego consultar clima
    const coords = await getCoordinates(parsed.planetName);

    // Si no se encuentran coordenadas, usar ubicación genérica (0,0)
    const weather = coords
      ? await getWeatherByLatLon(coords.lat, coords.lon)
      : await getWeatherByLatLon("0", "0");

    // Crear objeto a almacenar en DynamoDB
    const itemToStore = {
      ...parsed,
      weather,
      timestamp: Date.now(),
      source: "manual", // Indica que no expira como los datos de integración
    };

    // Crear comando de inserción y enviarlo a DynamoDB
    const command = new PutItemCommand({
      TableName: TABLE_NAME,
      Item: marshall(itemToStore),
    });

    await client.send(command);

    // Respuesta exitosa
    return {
      statusCode: 201,
      body: JSON.stringify({
        message: "Planeta almacenado correctamente",
        item: itemToStore,
      }),
    };
  } catch (error: any) {
    // Manejo de errores de validación
    if (error instanceof ZodError) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          // Se concatenan todos los mensajes de error en español
          error: error.errors.map((e) => e.message).join(", "),
        }),
      };
    }
    // Manejo de errores generales
    return {
      statusCode: 400,
      body: JSON.stringify({
        error: error.message || "Error en los datos enviados",
      }),
    };
  }
};
