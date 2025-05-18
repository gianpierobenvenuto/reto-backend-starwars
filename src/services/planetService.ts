/**
 * @file planetService.ts
 * @description Servicio para obtener información de un planeta, primero desde DynamoDB y luego desde SWAPI si no existe en base local.
 *              Fusiona el acceso a datos propios y externos bajo una única interfaz de consulta.
 *              Útil para verificar si el planeta ya fue almacenado manualmente antes de consultar APIs externas.
 * @author Gianpiero Benvenuto
 */

import { getPlanet as getPlanetFromSWAPI } from "./swapiService";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { logToCloudWatch } from "../utils/cloudwatchLogger"; // Importa el logger

// Nombre de la tabla DynamoDB
const TABLE_NAME = process.env.DYNAMO_TABLE!;
const client = new DynamoDBClient({});

/**
 * Busca un planeta almacenado localmente en DynamoDB.
 * @param planet Nombre del planeta (case-insensitive)
 * @returns Objeto del planeta si existe, o null si no está en base local
 */
async function getPlanetFromDB(planet: string) {
  await logToCloudWatch(`Consultando en DynamoDB: ${planet}`, "INFO");

  const command = new GetItemCommand({
    TableName: TABLE_NAME,
    Key: marshall({ id: planet.toLowerCase() }),
  });

  const result = await client.send(command);
  if (!result.Item) {
    await logToCloudWatch(`No se encontró en DynamoDB: ${planet}`, "INFO");
    return null;
  }

  await logToCloudWatch(`Planeta encontrado en DynamoDB: ${planet}`, "INFO");
  return unmarshall(result.Item);
}

/**
 * Obtiene la información de un planeta. Primero busca en DynamoDB;
 * si no lo encuentra, lo busca en SWAPI.
 *
 * @param planet Nombre del planeta a buscar
 * @returns Objeto con campos `name`, `climate` y `population`, o null si no se encuentra en ninguna fuente
 */
export async function getPlanet(planet: string) {
  // Primero busca en base de datos local (planetas almacenados manualmente)
  await logToCloudWatch(`Buscando planeta: ${planet}`, "INFO");

  const planetDB = await getPlanetFromDB(planet);
  if (planetDB) {
    await logToCloudWatch(`Planeta encontrado en DB: ${planet}`, "INFO");
    return planetDB;
  }

  // Si no está en DB, intenta en SWAPI
  try {
    await logToCloudWatch(
      `Planeta no encontrado en DB, buscando en SWAPI: ${planet}`,
      "INFO"
    );
    const planetSWAPI = await getPlanetFromSWAPI(planet);

    await logToCloudWatch(`Planeta encontrado en SWAPI: ${planet}`, "INFO");
    return {
      name: planetSWAPI.name.toLowerCase(),
      climate: planetSWAPI.climate,
      population: planetSWAPI.population,
    };
  } catch (error: unknown) {
    // Log de error si no se encuentra en SWAPI
    await logToCloudWatch(
      `Error al buscar planeta en SWAPI: ${planet}`,
      "ERROR"
    );
    return null;
  }
}
