import { handler } from "../src/handlers/historial";
import { APIGatewayProxyResult } from "aws-lambda";

jest.mock("../src/utils/auth", () => ({
  verifyToken: jest.fn(() => ({ valid: true })),
}));

// Mock del cliente DynamoDB y funciones usadas
jest.mock("@aws-sdk/client-dynamodb", () => {
  return {
    DynamoDBClient: jest.fn().mockImplementation(() => ({
      send: jest.fn().mockResolvedValue({
        Items: [
          {
            id: { S: "custom1" },
            name: { S: "Test Item" },
            description: { S: "Esto es un item de prueba" },
            timestamp: { N: "1747422425575" },
          },
          {
            id: { S: "tatooine" },
            planetName: { S: "Tatooine" },
            climate: { S: "arid" },
            population: { S: "200000" },
            weather: {
              S: '{"temperatureC":34.12,"description":"overcast clouds"}',
            },
            timestamp: { N: "1747422018665" },
          },
        ],
        LastEvaluatedKey: null,
      }),
    })),
    ScanCommand: jest.fn(),
  };
});

describe("historial handler", () => {
  it("should return a list of items", async () => {
    const event = {
      queryStringParameters: {
        limit: "5",
      },
    } as any;

    const context = {} as any;
    const callback = () => {};

    const result = (await handler(
      event,
      context,
      callback
    )) as APIGatewayProxyResult;
    const body = JSON.parse(result.body);

    expect(result.statusCode).toBe(200);
    expect(body).toHaveProperty("items");
    expect(Array.isArray(body.items)).toBe(true);
    expect(body.items.length).toBeGreaterThan(0);
    expect(body).toHaveProperty("lastKey");
  });
});
