import { getPlanet as getPlanetFromSWAPI } from "./swapiService";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

const TABLE_NAME = process.env.DYNAMO_TABLE!;
const client = new DynamoDBClient({});

async function getPlanetFromDB(planet: string) {
  const command = new GetItemCommand({
    TableName: TABLE_NAME,
    Key: marshall({ id: planet.toLowerCase() }),
  });
  const result = await client.send(command);
  if (!result.Item) return null;
  return unmarshall(result.Item);
}

export async function getPlanet(planet: string) {
  // Primero busca en DB local
  const planetDB = await getPlanetFromDB(planet);
  if (planetDB) return planetDB;

  // Si no está en DB, intenta en SWAPI
  try {
    const planetSWAPI = await getPlanetFromSWAPI(planet);
    return {
      name: planetSWAPI.name.toLowerCase(),
      climate: planetSWAPI.climate,
      population: planetSWAPI.population,
    };
  } catch {
    // Si no lo encuentra en SWAPI tampoco
    return null;
  }
}
