import { APIGatewayProxyHandler } from "aws-lambda";
import { z, ZodError } from "zod";
import axios from "axios";
import { getPlanet } from "../services/swapiService";
import { getWeatherByLatLon } from "../services/weatherService";
import { getCachedFusionado, cacheFusionado } from "../services/cacheService";
import { verifyToken } from "../utils/auth";

const querySchema = z.object({
  planeta: z.string().min(1, 'El parámetro "planeta" es obligatorio'),
});

// Función para obtener coordenadas por nombre usando Nominatim
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
    if (response.data.length === 0) return null;
    return { lat: response.data[0].lat, lon: response.data[0].lon };
  } catch {
    return null;
  }
}

export const handler: APIGatewayProxyHandler = async (event) => {
  // ✅ Verifica el token JWT
  const auth = verifyToken(event);
  if (!auth.valid) {
    return {
      statusCode: 401,
      body: JSON.stringify({ error: auth.error }),
    };
  }

  try {
    const query = querySchema.parse(event.queryStringParameters || {});
    const planet = query.planeta.toLowerCase();

    const cached = await getCachedFusionado(planet);
    if (cached) {
      return {
        statusCode: 200,
        body: JSON.stringify({ source: "cache", data: cached }),
      };
    }

    const planetData = await getPlanet(planet);
    const coords = await getCoordinates(planetData.name);

    const weatherData = coords
      ? await getWeatherByLatLon(coords.lat, coords.lon)
      : await getWeatherByLatLon("0", "0");

    const fusionado = {
      planetName: planetData.name,
      climate: planetData.climate,
      population: planetData.population,
      weather: weatherData,
      timestamp: Date.now(),
      source: "swapi",
    };

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
