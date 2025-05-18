/**
 * @file cacheService.ts
 * @description Servicio de utilidades para manejo de caché de planetas fusionados en DynamoDB.
 *              Permite almacenar y recuperar resultados fusionados, aplicando política de expiración para respuestas automáticas.
 * @author Gianpiero Benvenuto
 */

import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
} from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { logToCloudWatch } from "../utils/cloudwatchLogger"; // Importa el logger

// Nombre de la tabla DynamoDB donde se almacena la caché
const TABLE_NAME = process.env.DYNAMO_TABLE!;

// Cliente de DynamoDB
const client = new DynamoDBClient({});

/**
 * Recupera un resultado fusionado desde caché, si existe y no ha expirado.
 * @param planet Nombre del planeta (clave primaria)
 * @returns Objeto almacenado o null si no existe o expiró
 */
export async function getCachedFusionado(planet: string) {
  await logToCloudWatch(`Recuperando desde caché: ${planet}`, "INFO");

  const command = new GetItemCommand({
    TableName: TABLE_NAME,
    Key: marshall({ id: planet }),
  });

  const result = await client.send(command);
  if (!result.Item) {
    await logToCloudWatch(`No se encontró en caché: ${planet}`, "INFO");
    return null;
  }

  const item = unmarshall(result.Item);
  const now = Date.now();
  const cacheAge = now - item.timestamp;

  // Solo expira si fue generado automáticamente (de fuente externa SWAPI)
  if (item.source !== "manual" && cacheAge > 30 * 60 * 1000) {
    await logToCloudWatch(`Cache expirado para el planeta: ${planet}`, "INFO");
    return null;
  }

  await logToCloudWatch(
    `Cache válido encontrado para el planeta: ${planet}`,
    "INFO"
  );
  return item;
}

/**
 * Almacena en caché el resultado fusionado para un planeta determinado.
 * Si el dato ya existía, lo sobreescribe.
 * @param planet Nombre del planeta (clave primaria)
 * @param data Objeto de datos fusionados (clima, población, etc.)
 */
export async function cacheFusionado(planet: string, data: any) {
  const item = {
    id: planet,
    ...data,
    timestamp: Date.now(), // tiempo actual de almacenamiento
  };

  const command = new PutItemCommand({
    TableName: TABLE_NAME,
    Item: marshall(item),
  });

  await client.send(command);
  await logToCloudWatch(
    `Fusionado almacenado en caché para el planeta: ${planet}`,
    "INFO"
  );
}
