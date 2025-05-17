import { APIGatewayProxyHandler } from "aws-lambda";
import { z, ZodError } from "zod";
import axios from "axios";
import { getPlanet } from "../services/swapiService";
import { getWeatherByLatLon } from "../services/weatherService"; // adapta para consultar por coords
import { getCachedFusionado, cacheFusionado } from "../services/cacheService";

const querySchema = z.object({
  planet: z.string().min(1, 'El parámetro "planet" es obligatorio'),
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
      headers: { "User-Agent": "StarWarsApp/1.0" }, // Nominatim recomienda usar User-Agent
    });
    if (response.data.length === 0) return null;
    return { lat: response.data[0].lat, lon: response.data[0].lon };
  } catch {
    return null;
  }
}

export const handler: APIGatewayProxyHandler = async (event) => {
  try {
    const query = querySchema.parse(event.queryStringParameters || {});
    const planet = query.planet.toLowerCase();

    const cached = await getCachedFusionado(planet);
    if (cached) {
      return {
        statusCode: 200,
        body: JSON.stringify({ source: "cache", data: cached }),
      };
    }

    const planetData = await getPlanet(planet);

    // Intentamos obtener coordenadas dinámicas del planeta para clima real
    const coords = await getCoordinates(planetData.name);
    let weatherData;
    if (coords) {
      weatherData = await getWeatherByLatLon(coords.lat, coords.lon);
    } else {
      // fallback si no encontramos coords
      weatherData = await getWeatherByLatLon("0", "0"); // o una ciudad genérica
    }

    const fusionado = {
      planetName: planetData.name,
      climate: planetData.climate,
      population: planetData.population,
      weather: weatherData,
      timestamp: Date.now(),
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
