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
import { logToCloudWatch } from "../utils/cloudwatchLogger"; // Importa el logger

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
  // Log de inicio de la ejecución del handler
  await logToCloudWatch("Inicio de la ejecución del handler /almacenar");

  // Verificar autenticación JWT
  const auth = await verifyToken(event);
  if (!auth.valid) {
    await logToCloudWatch(`Autenticación fallida: ${auth.error}`, "ERROR");
    return {
      statusCode: 401,
      body: JSON.stringify({ error: auth.error }),
    };
  }

  try {
    // Validar existencia del cuerpo
    if (!event.body) {
      await logToCloudWatch("No se proporcionó cuerpo en la petición", "ERROR");
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

    // Log de datos validados
    await logToCloudWatch(`Datos validados: ${JSON.stringify(parsed)}`);

    // Obtener coordenadas del planeta para luego consultar clima
    const coords = await getCoordinates(parsed.planetName);
    if (!coords) {
      await logToCloudWatch(
        `No se encontraron coordenadas para el planeta: ${parsed.planetName}`,
        "WARNING"
      );
    }

    const weather = coords
      ? await getWeatherByLatLon(coords.lat, coords.lon)
      : await getWeatherByLatLon("0", "0");

    const itemToStore = {
      ...parsed,
      weather,
      timestamp: Date.now(),
      source: "manual",
    };

    const command = new PutItemCommand({
      TableName: TABLE_NAME,
      Item: marshall(itemToStore),
    });

    await client.send(command);

    // Log de éxito
    await logToCloudWatch(`Planeta almacenado: ${JSON.stringify(itemToStore)}`);

    return {
      statusCode: 201,
      body: JSON.stringify({
        message: "Planeta almacenado correctamente",
        item: itemToStore,
      }),
    };
  } catch (error: unknown) {
    // Manejo de errores de validación
    if (error instanceof ZodError) {
      await logToCloudWatch(
        `Errores de validación: ${error.errors
          .map((e) => e.message)
          .join(", ")}`,
        "ERROR"
      );
      return {
        statusCode: 400,
        body: JSON.stringify({
          error: error.errors.map((e) => e.message).join(", "),
        }),
      };
    }

    // Verificación del tipo de error
    if (error instanceof Error) {
      // Log de error general
      await logToCloudWatch(
        `Error en el procesamiento: ${error.message}`,
        "ERROR"
      );
    } else {
      // En caso de que el error no sea una instancia de Error, loguear el error desconocido
      await logToCloudWatch(
        `Error desconocido en el procesamiento: ${String(error)}`,
        "ERROR"
      );
    }

    return {
      statusCode: 400,
      body: JSON.stringify({
        error: error instanceof Error ? error.message : "Error desconocido",
      }),
    };
  }
};
