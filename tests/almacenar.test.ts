/**
 * @file almacenar.test.ts
 * @description Pruebas unitarias para el handler `almacenar`.
 *              Verifica los diferentes flujos: éxito al guardar, falta de body, y validación de campos requeridos.
 * @author Gianpiero Benvenuto
 */

import { handler } from "../src/handlers/almacenar";
import { APIGatewayProxyResult } from "aws-lambda";

// tests/almacenar.test.ts
jest.mock("../src/utils/cloudwatchLogger", () => ({
  logToCloudWatch: jest.fn(),
}));

// Mock de verifyToken para simular siempre autenticación válida
jest.mock("../src/utils/auth", () => ({
  verifyToken: () => ({ valid: true, payload: { userId: "test" } }),
}));

// Mock de DynamoDB: simulamos el cliente y el comando PutItem
jest.mock("@aws-sdk/client-dynamodb", () => {
  return {
    DynamoDBClient: jest.fn().mockImplementation(() => ({
      send: jest.fn().mockResolvedValue({}), // send siempre resuelve exitosamente
    })),
    PutItemCommand: jest.fn(), // solo necesitamos el constructor
  };
});

// Mock del servicio de geolocalización para devolver coordenadas fijas
jest.mock("../src/services/geoService", () => ({
  getCoordinates: jest.fn().mockResolvedValue({ lat: "0", lon: "0" }),
}));

// Mock del servicio de clima para devolver datos fijos
jest.mock("../src/services/weatherService", () => ({
  getWeatherByLatLon: jest.fn().mockResolvedValue({
    temperatureC: 20,
    description: "cielo despejado",
  }),
}));

describe("handler de almacenar", () => {
  it("debería guardar el ítem y devolver éxito", async () => {
    // Evento simulado con body correcto
    const event = {
      body: JSON.stringify({
        id: "custom1",
        planetName: "Test Planet",
        climate: "temperate",
      }),
    } as any;

    // Ejecutamos el handler
    const result = (await handler(
      event,
      {} as any,
      () => {}
    )) as APIGatewayProxyResult;
    const body = JSON.parse(result.body);

    // Verificamos el código HTTP y estructura de la respuesta
    expect(result.statusCode).toBe(201);
    expect(body).toHaveProperty("message", "Planeta almacenado correctamente");
    expect(body.item).toHaveProperty("id", "custom1");
  });

  it("debería devolver 400 si falta el body", async () => {
    // Evento con body nulo
    const event = { body: null } as any;

    const result = (await handler(
      event,
      {} as any,
      () => {}
    )) as APIGatewayProxyResult;
    const body = JSON.parse(result.body);

    // Esperamos un error de validación de presencia de body
    expect(result.statusCode).toBe(400);
    expect(body).toHaveProperty(
      "error",
      "No se proporcionó cuerpo en la petición"
    );
  });

  it("debería devolver 400 si falta el campo id", async () => {
    // Evento con body sin la propiedad 'id'
    const event = {
      body: JSON.stringify({ planetName: "Tatooine", climate: "arid" }),
    } as any;

    const result = (await handler(
      event,
      {} as any,
      () => {}
    )) as APIGatewayProxyResult;
    const body = JSON.parse(result.body);

    // El error debe contener el mensaje personalizado de Zod
    expect(result.statusCode).toBe(400);
    expect(body.error).toContain('El campo "id" es obligatorio');
  });
});
