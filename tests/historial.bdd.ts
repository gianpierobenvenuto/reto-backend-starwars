/**
 * @file historial.bdd.ts
 * @description Pruebas BDD para el handler GET /historial.
 *              Recupera registros desde DynamoDB con paginación y validación de parámetros.
 * @author Gianpiero Benvenuto
 */

import { defineFeature, loadFeature } from "jest-cucumber";
import { resolve } from "path";
import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";

// Mock de la autenticación JWT para simular siempre un token válido
jest.mock("../src/utils/auth", () => ({
  verifyToken: jest.fn(() => ({ valid: true, payload: { userId: "test" } })),
}));

// --- Mocks de DynamoDB antes de importar el handler ---
const mockSend = jest.fn();
jest.mock("@aws-sdk/client-dynamodb", () => ({
  DynamoDBClient: jest.fn().mockImplementation(() => ({ send: mockSend })),
  ScanCommand: jest.fn(),
}));

import { handler } from "../src/handlers/historial";

// Mocks de utilidades
jest.mock("../src/utils/cloudwatchLogger", () => ({
  logToCloudWatch: jest.fn().mockResolvedValue(undefined),
}));

const feature = loadFeature(
  resolve(__dirname, "../features/historial.feature")
);

defineFeature(feature, (test) => {
  let response: APIGatewayProxyResult;
  let event: APIGatewayProxyEvent;

  const goodItems = [
    { id: "1", timestamp: 1000 },
    { id: "2", timestamp: 2000 },
  ];
  const lastEvaluatedKey = { id: "2" };

  beforeEach(() => {
    mockSend.mockReset();
    mockSend.mockResolvedValue({
      Items: goodItems.map((item) => ({
        id: { S: item.id },
        timestamp: { N: String(item.timestamp) },
      })),
      LastEvaluatedKey: lastEvaluatedKey,
    });
  });

  test("Recuperar historial sin parámetros", ({ given, when, then, and }) => {
    given('el endpoint GET "/historial" está disponible', () => {
      expect(handler).toBeDefined();
    });

    when('hago una petición al handler con path "/historial"', async () => {
      event = { path: "/historial", queryStringParameters: {} } as any;
      response = await handler(event);
    });

    then("recibo un statusCode 200", () => {
      expect(response.statusCode).toBe(200);
    });

    and('la respuesta contiene "items"', () => {
      const body = JSON.parse(response.body);
      expect(Array.isArray(body.items)).toBe(true);
    });

    and('la respuesta contiene "lastKey"', () => {
      const body = JSON.parse(response.body);
      expect(body).toHaveProperty("lastKey");
    });
  });

  test("Recuperar historial con limit personalizado", ({
    given,
    when,
    then,
    and,
  }) => {
    given('el endpoint GET "/historial" está disponible', () => {
      expect(handler).toBeDefined();
    });

    when(
      'hago una petición al handler con path "/historial?limit=5"',
      async () => {
        event = {
          path: "/historial",
          queryStringParameters: { limit: "5" },
        } as any;
        response = await handler(event);
      }
    );

    then("recibo un statusCode 200", () => {
      expect(response.statusCode).toBe(200);
    });

    and('la respuesta contiene "items"', () => {
      const body = JSON.parse(response.body);
      expect(Array.isArray(body.items)).toBe(true);
    });

    and('la respuesta contiene "lastKey"', () => {
      const body = JSON.parse(response.body);
      expect(body).toHaveProperty("lastKey");
    });
  });

  test("Parámetro limit inválido", ({ given, when, then, and }) => {
    given('el endpoint GET "/historial" está disponible', () => {
      expect(handler).toBeDefined();
    });

    when(
      'hago una petición al handler con path "/historial?limit=abc"',
      async () => {
        event = {
          path: "/historial",
          queryStringParameters: { limit: "abc" },
        } as any;
        response = await handler(event);
      }
    );

    then("recibo un statusCode 400", () => {
      expect(response.statusCode).toBe(400);
    });

    and('la respuesta contiene "Expected number"', () => {
      expect(response.body).toContain("Expected number");
    });
  });
});
