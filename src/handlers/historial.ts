import { APIGatewayProxyHandler } from "aws-lambda";
import { DynamoDBClient, ScanCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { z, ZodError } from "zod";
import { verifyToken } from "../utils/auth";

const TABLE_NAME = process.env.DYNAMO_TABLE!;
const client = new DynamoDBClient({});

const querySchema = z.object({
  limit: z.preprocess((val) => {
    if (typeof val === "string" && /^\d+$/.test(val)) {
      return Number(val);
    }
    return val;
  }, z.number().int().positive().optional()),
  lastKey: z.string().optional(),
});

export const handler: APIGatewayProxyHandler = async (event) => {
  // 🔐 Verificar token JWT
  const auth = verifyToken(event);
  if (!auth.valid) {
    return {
      statusCode: 401,
      body: JSON.stringify({ error: auth.error }),
    };
  }

  try {
    const query = querySchema.parse(event.queryStringParameters || {});
    const limit = query.limit ?? 10;

    const lastKey = query.lastKey
      ? JSON.parse(decodeURIComponent(query.lastKey))
      : undefined;

    const params: any = {
      TableName: TABLE_NAME,
      Limit: limit,
    };

    if (lastKey) {
      params.ExclusiveStartKey = lastKey;
    }

    const command = new ScanCommand(params);
    const response = await client.send(command);

    const items = response.Items
      ? response.Items.map((item) => unmarshall(item))
      : [];

    items.sort((a, b) => b.timestamp - a.timestamp);

    return {
      statusCode: 200,
      body: JSON.stringify({
        items,
        lastKey: response.LastEvaluatedKey
          ? encodeURIComponent(JSON.stringify(response.LastEvaluatedKey))
          : null,
      }),
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
      body: JSON.stringify({ error: error.message }),
    };
  }
};
