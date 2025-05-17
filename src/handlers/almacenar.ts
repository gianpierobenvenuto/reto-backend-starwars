import { APIGatewayProxyHandler } from "aws-lambda";
import { z, ZodError } from "zod";
import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { verifyToken } from "../utils/auth";

const TABLE_NAME = process.env.DYNAMO_TABLE!;
const client = new DynamoDBClient({});

const bodySchema = z.object({
  id: z
    .string({
      required_error: 'Field "id" is required',
      invalid_type_error: 'Field "id" must be a string',
    })
    .min(1, 'Field "id" is required'),
});

export const handler: APIGatewayProxyHandler = async (event) => {
  const auth = verifyToken(event);
  if (!auth.valid) {
    return {
      statusCode: 401,
      body: JSON.stringify({ error: auth.error }),
    };
  }

  try {
    if (!event.body) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "No body provided" }),
      };
    }

    const data = JSON.parse(event.body);
    const parsed = bodySchema.parse(data);

    const itemToStore = {
      ...parsed,
      timestamp: Date.now(),
    };

    const command = new PutItemCommand({
      TableName: TABLE_NAME,
      Item: marshall(itemToStore),
    });

    await client.send(command);

    return {
      statusCode: 201,
      body: JSON.stringify({
        message: "Item stored successfully",
        item: itemToStore,
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
      statusCode: 400,
      body: JSON.stringify({
        error: error.message || "Error in sent data",
      }),
    };
  }
};
