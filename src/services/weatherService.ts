/**
 * @file weatherService.ts
 * @description Servicio para consultar el clima actual utilizando la API de OpenWeatherMap.
 *              Soporta consultas tanto por nombre de ciudad como por coordenadas (lat/lon).
 *              Devuelve temperatura en grados Celsius y una descripción del clima.
 * @author Gianpiero Benvenuto
 */

import axios from "axios";

// Clave de acceso a la API de OpenWeatherMap (se espera en variable de entorno)
const API_KEY = process.env.WEATHER_API_KEY || "";

/**
 * Consulta la API de OpenWeatherMap para obtener clima actual usando nombre de ciudad.
 *
 * @param city Nombre del lugar a consultar (ej: "Lima", "Tatooine")
 * @returns Objeto con temperatura en °C y descripción del clima
 */
export async function getWeather(city: string) {
  const response = await axios.get(
    `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(
      city
    )}&appid=${API_KEY}&units=metric`
  );

  const data = response.data;

  return {
    temperatureC: data.main.temp,
    description: data.weather[0].description,
  };
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
  const response = await axios.get(
    `https://api.openweathermap.org/data/2.5/weather?lat=${lat}&lon=${lon}&appid=${API_KEY}&units=metric`
  );

  const data = response.data;

  return {
    temperatureC: data.main.temp,
    description: data.weather[0].description,
  };
}
