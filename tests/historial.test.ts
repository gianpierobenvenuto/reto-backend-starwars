/**
 * @file historial.test.ts
 * @description Pruebas unitarias para el handler `historial`. Verifica que retorne correctamente
 *              una lista de elementos paginados desde DynamoDB y que respete la autenticación JWT.
 * @author Gianpiero Benvenuto
 */

import { handler } from "../src/handlers/historial";
import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
  Callback,
} from "aws-lambda";

// tests/historial.test.ts
jest.mock("../src/utils/cloudwatchLogger", () => ({
  logToCloudWatch: jest.fn(),
}));

// Mock de la función verifyToken para simular siempre autenticación válida
jest.mock("../src/utils/auth", () => ({
  verifyToken: jest.fn(() => ({ valid: true })),
}));

// Mock del cliente DynamoDB y de ScanCommand para devolver resultados de prueba
jest.mock("@aws-sdk/client-dynamodb", () => {
  return {
    DynamoDBClient: jest.fn().mockImplementation(() => ({
      // send regresará un objeto con Items y LastEvaluatedKey
      send: jest.fn().mockResolvedValue({
        Items: [
          {
            id: { S: "custom1" },
            planetName: { S: "Test Planet" },
            climate: { S: "temperate" },
            population: { S: "1000" },
            weather: {
              S: '{"temperatureC":20,"description":"cielo despejado"}',
            },
            timestamp: { N: "1747422425575" },
          },
        ],
        LastEvaluatedKey: null,
      }),
    })),
    ScanCommand: jest.fn(), // sólo necesitamos el constructor
  };
});

describe("handler de historial", () => {
  it("debería devolver una lista de elementos", async () => {
    // Simular un evento con parámetro de paginación 'limit'
    const event = {
      queryStringParameters: { limit: "5" },
    } as unknown as APIGatewayProxyEvent;

    // Ejecutar el handler solo con el evento
    const result = (await handler(event)) as APIGatewayProxyResult;
    const body = JSON.parse(result.body);

    // Validaciones de la respuesta
    expect(result.statusCode).toBe(200);
    expect(body).toHaveProperty("items"); // Debe incluir 'items'
    expect(Array.isArray(body.items)).toBe(true); // 'items' debe ser un arreglo
    expect(body.items.length).toBeGreaterThan(0); // Debe tener al menos un elemento
    expect(body).toHaveProperty("lastKey"); // Debe incluir 'lastKey'
  });
});
