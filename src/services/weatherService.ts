/**
 * @file weatherService.ts
 * @description Servicio para consultar el clima actual utilizando la API de OpenWeatherMap.
 *              Soporta consultas tanto por nombre de ciudad como por coordenadas (lat/lon).
 *              Devuelve temperatura en grados Celsius y una descripción del clima.
 * @author Gianpiero Benvenuto
 */

import axios from "axios";
import { logToCloudWatch } from "../utils/cloudwatchLogger"; // Importa el logger

// Clave de acceso a la API de OpenWeatherMap (se espera en variable de entorno)
const API_KEY = process.env.WEATHER_API_KEY || "";

/**
 * Consulta la API de OpenWeatherMap para obtener clima actual usando nombre de ciudad.
 *
 * @param city Nombre del lugar a consultar (ej: "Lima", "Tatooine")
 * @returns Objeto con temperatura en °C y descripción del clima
 */
export async function getWeather(city: string) {
  // Log de la solicitud a OpenWeatherMap
  await logToCloudWatch(`Consultando clima para la ciudad: ${city}`, "INFO");

  try {
    const response = await axios.get(
      `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(
        city
      )}&appid=${API_KEY}&units=metric`
    );

    const data = response.data;

    // Log de éxito al obtener el clima
    await logToCloudWatch(
      `Clima obtenido para la ciudad ${city}: ${data.main.temp}°C, ${data.weather[0].description}`,
      "INFO"
    );

    return {
      temperatureC: data.main.temp,
      description: data.weather[0].description,
    };
  } catch (error: unknown) {
    // Verificación del tipo de error
    if (error instanceof Error) {
      // Log de error si la consulta falla
      await logToCloudWatch(
        `Error al consultar el clima para ${city}: ${error.message}`,
        "ERROR"
      );
    } else {
      // En caso de que el error no sea una instancia de Error, loguear el error desconocido
      await logToCloudWatch(
        `Error desconocido al consultar el clima para ${city}`,
        "ERROR"
      );
    }
    throw new Error("Error al consultar el clima");
  }
}

/**
 * Consulta la API de OpenWeatherMap utilizando coordenadas geográficas.
 *
 * @param lat Latitud del lugar
 * @param lon Longitud del lugar
 * @returns Objeto con temperatura en °C y descripción del clima
 */
export async function getWeatherByLatLon(
  lat: string | number,
  lon: string | number
) {
  // Log de la solicitud a OpenWeatherMap con coordenadas
  await logToCloudWatch(
    `Consultando clima para las coordenadas lat: ${lat}, lon: ${lon}`,
    "INFO"
  );

  try {
    const response = await axios.get(
      `https://api.openweathermap.org/data/2.5/weather?lat=${lat}&lon=${lon}&appid=${API_KEY}&units=metric`
    );

    const data = response.data;

    // Log de éxito al obtener el clima
    await logToCloudWatch(
      `Clima obtenido para coordenadas lat: ${lat}, lon: ${lon}: ${data.main.temp}°C, ${data.weather[0].description}`,
      "INFO"
    );

    return {
      temperatureC: data.main.temp,
      description: data.weather[0].description,
    };
  } catch (error: unknown) {
    // Verificación del tipo de error
    if (error instanceof Error) {
      // Log de error si la consulta falla
      await logToCloudWatch(
        `Error al consultar el clima para las coordenadas lat: ${lat}, lon: ${lon}: ${error.message}`,
        "ERROR"
      );
    } else {
      // En caso de que el error no sea una instancia de Error, loguear el error desconocido
      await logToCloudWatch(
        `Error desconocido al consultar el clima para las coordenadas lat: ${lat}, lon: ${lon}`,
        "ERROR"
      );
    }
    throw new Error("Error al consultar el clima");
  }
}
