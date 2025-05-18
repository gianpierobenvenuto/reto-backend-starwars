/**
 * @file swapiService.ts
 * @description Servicio que consulta la Star Wars API (SWAPI) para obtener información básica de un planeta.
 *              Utiliza búsqueda por nombre y retorna los campos clave utilizados en el sistema.
 *              SWAPI es una API pública sin autenticación ni límites estrictos.
 * @author Gianpiero Benvenuto
 */

import axios from "axios";

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
  const response = await axios.get(`${BASE_URL}/planets/?search=${name}`);
  const planet = response.data.results[0];

  if (!planet) {
    throw new Error("Planeta no encontrado en SWAPI");
  }

  return {
    name: planet.name,
    climate: planet.climate,
    population: planet.population,
  };
}
