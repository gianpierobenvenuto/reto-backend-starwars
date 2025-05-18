import { APIGatewayProxyHandler } from "aws-lambda";
import { z, ZodError } from "zod";
import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { verifyToken } from "../utils/auth";
import { getCoordinates } from "../services/geoService";
import { getWeatherByLatLon } from "../services/weatherService";

const TABLE_NAME = process.env.DYNAMO_TABLE!;
const client = new DynamoDBClient({});

const bodySchema = z.object({
  id: z.string().min(1, 'El campo "id" es obligatorio'),
  planetName: z.string(),
  climate: z.string(),
  population: z.string().optional(),
});

export const handler: APIGatewayProxyHandler = async (event) => {
  const auth = verifyToken(event);
  if (!auth.valid) {
    return {
      statusCode: 401,
      body: JSON.stringify({ error: auth.error }),
    };
  }

  try {
    if (!event.body) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          error: "No se proporcionó cuerpo en la petición",
        }),
      };
    }

    const data = JSON.parse(event.body);
    const parsed = bodySchema.parse(data);

    // Obtener coordenadas del planeta para consultar clima
    const coords = await getCoordinates(parsed.planetName);

    // Si no hay coords, fallback a (0,0)
    const weather = coords
      ? await getWeatherByLatLon(coords.lat, coords.lon)
      : await getWeatherByLatLon("0", "0");

    const itemToStore = {
      ...parsed,
      weather,
      timestamp: Date.now(),
      source: "manual", // ✅ Esto previene la expiración automática
    };

    const command = new PutItemCommand({
      TableName: TABLE_NAME,
      Item: marshall(itemToStore),
    });

    await client.send(command);

    return {
      statusCode: 201,
      body: JSON.stringify({
        message: "Planeta almacenado correctamente",
        item: itemToStore,
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
      statusCode: 400,
      body: JSON.stringify({
        error: error.message || "Error en los datos enviados",
      }),
    };
  }
};
