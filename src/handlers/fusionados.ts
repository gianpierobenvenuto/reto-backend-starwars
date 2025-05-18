/**
 * @file fusionados.ts
 * @description Lambda handler para el endpoint GET /fusionados.
 *              Fusiona datos del planeta desde la API SWAPI y datos meteorológicos obtenidos por coordenadas.
 *              Incluye autenticación con JWT, validación con Zod, y uso de caché para optimizar llamadas.
 * @author Gianpiero Benvenuto
 */

import { APIGatewayProxyHandler } from "aws-lambda";
import { z, ZodError } from "zod";
import axios from "axios";
import { getPlanet } from "../services/swapiService";
import { getWeatherByLatLon } from "../services/weatherService";
import { getCachedFusionado, cacheFusionado } from "../services/cacheService";
import { verifyToken } from "../utils/auth";

// Esquema de validación del parámetro "planeta"
const querySchema = z.object({
  planeta: z.string().min(1, 'El parámetro "planeta" es obligatorio'),
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
      headers: { "User-Agent": "StarWarsApp/1.0" }, // Cumple con requisitos de Nominatim
    });
    if (response.data.length === 0) return null;
    return { lat: response.data[0].lat, lon: response.data[0].lon };
  } catch {
    return null;
  }
}

/**
 * Lambda principal para fusionar información del planeta y su clima.
 * Endpoint: GET /fusionados?planeta=Tatooine
 * Autenticación: Requiere JWT en el encabezado de autorización.
 * Lógica:
 *   - Valida parámetro "planeta"
 *   - Verifica cache de consulta
 *   - Si no hay cache, consulta SWAPI y servicio de clima
 *   - Fusiona datos, guarda en caché, y responde
 */
export const handler: APIGatewayProxyHandler = async (event) => {
  // Verifica JWT
  const auth = verifyToken(event);
  if (!auth.valid) {
    return {
      statusCode: 401,
      body: JSON.stringify({ error: auth.error }),
    };
  }

  try {
    // Valida el parámetro de consulta
    const query = querySchema.parse(event.queryStringParameters || {});
    const planet = query.planeta.toLowerCase();

    // Intenta recuperar desde caché
    const cached = await getCachedFusionado(planet);
    if (cached) {
      return {
        statusCode: 200,
        body: JSON.stringify({ source: "cache", data: cached }),
      };
    }

    // Obtiene información del planeta desde SWAPI
    const planetData = await getPlanet(planet);

    // Obtiene coordenadas del planeta y luego clima
    const coords = await getCoordinates(planetData.name);
    const weatherData = coords
      ? await getWeatherByLatLon(coords.lat, coords.lon)
      : await getWeatherByLatLon("0", "0"); // fallback si no hay coordenadas

    // Arma el objeto fusionado final
    const fusionado = {
      planetName: planetData.name,
      climate: planetData.climate,
      population: planetData.population,
      weather: weatherData,
      timestamp: Date.now(),
      source: "swapi",
    };

    // Guarda resultado en caché
    await cacheFusionado(planet, fusionado);

    return {
      statusCode: 200,
      body: JSON.stringify({ source: "live", data: fusionado }),
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
      body: JSON.stringify({ error: "Error interno del servidor" }),
    };
  }
};
