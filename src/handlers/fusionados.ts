/**
 * @file fusionados.ts
 * @description Lambda handler para el endpoint GET /fusionados.
 *              Fusiona datos del planeta desde la API SWAPI y datos meteorológicos obtenidos por coordenadas.
 *              Incluye autenticación con JWT, validación con Zod, y uso de caché para optimizar llamadas.
 * @author Gianpiero Benvenuto
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { z, ZodError } from "zod";
import axios from "axios";
import { getPlanet } from "../services/swapiService";
import { getWeatherByLatLon } from "../services/weatherService";
import { getCachedFusionado, cacheFusionado } from "../services/cacheService";
import { verifyToken } from "../utils/auth";
import { logToCloudWatch } from "../utils/cloudwatchLogger";

// Esquema de validación del parámetro "planeta", con mensaje usando comillas simples
const querySchema = z.object({
  planeta: z
    .string({ required_error: "El parámetro 'planeta' es obligatorio" })
    .min(1, "El parámetro 'planeta' es obligatorio"),
});

/**
 * Utiliza la API pública Nominatim para obtener coordenadas geográficas
 * a partir del nombre de un planeta (placeName).
 * Retorna lat/lon como strings o null si no se encuentra.
 */
async function getCoordinates(
  placeName: string
): Promise<{ lat: string; lon: string } | null> {
  try {
    const url = `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(
      placeName
    )}&format=json&limit=1`;
    const response = await axios.get(url, {
      headers: { "User-Agent": "StarWarsApp/1.0" },
    });
    if (!Array.isArray(response.data) || response.data.length === 0) {
      return null;
    }
    return { lat: response.data[0].lat, lon: response.data[0].lon };
  } catch {
    return null;
  }
}

/**
 * Lambda principal para fusionar información del planeta y su clima.
 * Endpoint: GET /fusionados?planeta=Tatooine
 * Autenticación: Requiere JWT en el encabezado de autorización.
 */
export const handler = async (
  event: APIGatewayProxyEvent,
  _context: any,
  _callback: any
): Promise<APIGatewayProxyResult> => {
  // Log de la ruta solicitada
  await logToCloudWatch(`Ruta solicitada: ${event.path}`, "INFO");

  // Verifica JWT
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
    // Validación del parámetro de consulta
    const { planeta } = querySchema.parse(event.queryStringParameters || {});
    const planet = planeta.toLowerCase();

    await logToCloudWatch(`Parámetro validado: ${planet}`, "INFO");

    // Intento de obtener del caché
    const cached = await getCachedFusionado(planet);
    if (cached) {
      await logToCloudWatch(`Cache hit para el planeta: ${planet}`, "INFO");
      return {
        statusCode: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source: "cache", data: cached }),
      };
    }
    await logToCloudWatch(`Cache miss para el planeta: ${planet}`, "INFO");

    // Consulta a SWAPI
    const planetData = await getPlanet(planet);
    // Obtiene coordenadas y luego clima
    const coords = await getCoordinates(planetData.name);
    const weatherData = coords
      ? await getWeatherByLatLon(coords.lat, coords.lon)
      : await getWeatherByLatLon("0", "0");

    // Construye el objeto fusionado
    const fusionado = {
      planetName: planetData.name,
      climate: planetData.climate,
      population: planetData.population,
      weather: weatherData,
      timestamp: Date.now(),
      source: "swapi",
    };

    // Guarda en caché
    await cacheFusionado(planet, fusionado);
    await logToCloudWatch(
      `Fusionado creado y almacenado para el planeta: ${planet}`,
      "INFO"
    );

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source: "live", data: fusionado }),
    };
  } catch (err: unknown) {
    // Errores de validación Zod
    if (err instanceof ZodError) {
      const msg = err.errors.map((e) => e.message).join(", ");
      await logToCloudWatch(`Errores de validación: ${msg}`, "ERROR");
      return {
        statusCode: 400,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error: msg }),
      };
    }
    // Otros errores
    const message = err instanceof Error ? err.message : "Error desconocido";
    await logToCloudWatch(`Error interno del servidor: ${message}`, "ERROR");
    return {
      statusCode: 500,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: message }),
    };
  }
};
