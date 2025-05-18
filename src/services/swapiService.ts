/**
 * @file swapiService.ts
 * @description Servicio que consulta la Star Wars API (SWAPI) para obtener información básica de un planeta.
 *              Utiliza búsqueda por nombre y retorna los campos clave utilizados en el sistema.
 *              SWAPI es una API pública sin autenticación ni límites estrictos.
 * @author Gianpiero Benvenuto
 */

import axios from "axios";
import { logToCloudWatch } from "../utils/cloudwatchLogger"; // Importa el logger

// URL base de la Star Wars API
const BASE_URL = "https://swapi.py4e.com/api";

/**
 * Realiza una búsqueda en SWAPI por nombre de planeta y devuelve sus datos básicos.
 *
 * @param name Nombre del planeta (ej. "Tatooine")
 * @returns Objeto con campos `name`, `climate` y `population`
 * @throws Si no se encuentra el planeta en los resultados
 */
export async function getPlanet(name: string) {
  // Log de la solicitud a SWAPI
  await logToCloudWatch(`Consultando SWAPI para el planeta: ${name}`, "INFO");

  try {
    const response = await axios.get(`${BASE_URL}/planets/?search=${name}`);
    const planet = response.data.results[0];

    if (!planet) {
      // Log cuando no se encuentra el planeta
      await logToCloudWatch(`Planeta no encontrado en SWAPI: ${name}`, "ERROR");
      throw new Error("Planeta no encontrado en SWAPI");
    }

    // Log de éxito al encontrar el planeta
    await logToCloudWatch(`Planeta encontrado en SWAPI: ${name}`, "INFO");

    return {
      name: planet.name,
      climate: planet.climate,
      population: planet.population,
    };
  } catch (error: unknown) {
    // Verificación del tipo de error
    if (error instanceof Error) {
      // Log de error si la consulta falla
      await logToCloudWatch(
        `Error al consultar SWAPI para el planeta: ${name}. Error: ${error.message}`,
        "ERROR"
      );
    } else {
      // En caso de que el error no sea una instancia de Error, loguear el error desconocido
      await logToCloudWatch(
        `Error desconocido al consultar SWAPI para el planeta: ${name}`,
        "ERROR"
      );
    }
    throw new Error("Error al consultar SWAPI");
  }
}
