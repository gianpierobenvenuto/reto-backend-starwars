/**
 * @file fusionado.ts
 * @description Define la estructura del objeto Fusionado, que representa
 *              la combinación de datos de un planeta de SWAPI y su información meteorológica.
 * @author Gianpiero Benvenuto
 */

/**
 * Representa un planeta fusionado con datos de clima.
 */
export interface Fusionado {
  /**
   * Nombre del planeta (proveniente de SWAPI).
   */
  planetName: string;

  /**
   * Clima reportado por SWAPI (puede ser una descripción como "arid", "temperate", "tropical", "frozen", etc.).
   */
  climate: string;

  /**
   * Población del planeta (como string, según lo provee SWAPI).
   */
  population: string;

  /**
   * Información meteorológica basada en coordenadas geográficas.
   */
  weather: {
    /**
     * Temperatura en grados Celsius.
     */
    temperatureC: number;

    /**
     * Descripción del clima actual (por ejemplo, "Clear sky").
     */
    description: string;
  };

  /**
   * Marca de tiempo de creación del objeto fusionado (en milisegundos desde epoch).
   */
  timestamp: number;
}
