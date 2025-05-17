import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
} from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

const TABLE_NAME = process.env.DYNAMO_TABLE!;
const client = new DynamoDBClient({});

export async function getCachedFusionado(planet: string) {
  const command = new GetItemCommand({
    TableName: TABLE_NAME,
    Key: marshall({ id: planet }),
  });

  const result = await client.send(command);
  if (!result.Item) return null;

  const item = unmarshall(result.Item);
  const now = Date.now();
  const cacheAge = now - item.timestamp;

  if (cacheAge > 30 * 60 * 1000) return null; // más de 30 minutos

  return item;
}

export async function cacheFusionado(planet: string, data: any) {
  const item = {
    id: planet,
    ...data,
    timestamp: Date.now(),
  };

  const command = new PutItemCommand({
    TableName: TABLE_NAME,
    Item: marshall(item),
  });

  await client.send(command);
}
