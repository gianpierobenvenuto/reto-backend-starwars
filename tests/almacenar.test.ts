import { handler } from "../src/handlers/almacenar";
import { APIGatewayProxyResult } from "aws-lambda";

/* Mock verifyToken to always be valid */
jest.mock("../src/utils/auth", () => ({
  verifyToken: () => ({ valid: true, payload: { userId: "test" } }),
}));

/* Mock DynamoDB */
jest.mock("@aws-sdk/client-dynamodb", () => {
  return {
    DynamoDBClient: jest.fn().mockImplementation(() => ({
      send: jest.fn().mockResolvedValue({}),
    })),
    PutItemCommand: jest.fn(),
  };
});

describe("almacenar handler", () => {
  it("should store item and return success", async () => {
    const event = {
      body: JSON.stringify({
        id: "custom1",
        name: "Test Item",
        description: "This is a test item",
      }),
    } as any;

    const result = (await handler(
      event,
      {} as any,
      () => {}
    )) as APIGatewayProxyResult;
    const body = JSON.parse(result.body);

    expect(result.statusCode).toBe(201);
    expect(body).toHaveProperty("message", "Item stored successfully");
    expect(body.item).toHaveProperty("id", "custom1");
  });

  it("should return 400 if body is missing", async () => {
    const event = { body: null } as any;

    const result = (await handler(
      event,
      {} as any,
      () => {}
    )) as APIGatewayProxyResult;
    const body = JSON.parse(result.body);

    expect(result.statusCode).toBe(400);
    expect(body).toHaveProperty("error", "No body provided");
  });

  it("should return 400 if id is missing", async () => {
    const event = { body: JSON.stringify({ name: "No ID" }) } as any;

    const result = (await handler(
      event,
      {} as any,
      () => {}
    )) as APIGatewayProxyResult;
    const body = JSON.parse(result.body);

    expect(result.statusCode).toBe(400);
    expect(body).toHaveProperty("error", 'Field "id" is required');
  });
});
