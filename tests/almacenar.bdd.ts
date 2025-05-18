/**
 * @file almacenar.bdd.ts
 * @description Pruebas BDD para el handler POST /almacenar usando Jest-Cucumber.
 *              Define los escenarios en Gherkin y los mapea a step definitions.
 * @author Gianpiero Benvenuto
 */

import { defineFeature, loadFeature } from "jest-cucumber";
import { resolve } from "path";
import { APIGatewayProxyResult } from "aws-lambda";
import { handler } from "../src/handlers/almacenar";

// Carga el feature Gherkin desde el directorio features
const feature = loadFeature(
  resolve(__dirname, "../features/almacenar.feature")
);

// Mock del logger para evitar llamadas reales a CloudWatch durante las pruebas
jest.mock("../src/utils/cloudwatchLogger", () => ({
  logToCloudWatch: jest.fn().mockResolvedValue(undefined),
}));

// **** mocks de dependencias externas ****
// Mock de la autenticación JWT para simular siempre un token válido
jest.mock("../src/utils/auth", () => ({
  verifyToken: () => ({ valid: true, payload: { userId: "test" } }),
}));
// Mock de DynamoDBClient y PutItemCommand para aislar la capa de persistencia
jest.mock("@aws-sdk/client-dynamodb", () => ({
  DynamoDBClient: jest
    .fn()
    .mockImplementation(() => ({ send: jest.fn().mockResolvedValue({}) })),
  PutItemCommand: jest.fn(),
}));
// Mock del servicio de geolocalización para devolver coordenadas fijas
jest.mock("../src/services/geoService", () => ({
  getCoordinates: jest.fn().mockResolvedValue({ lat: "0", lon: "0" }),
}));
// Mock del servicio de clima para devolver un resultado fijo
jest.mock("../src/services/weatherService", () => ({
  getWeatherByLatLon: jest
    .fn()
    .mockResolvedValue({ temperatureC: 20, description: "cielo despejado" }),
}));

// Definición de los escenarios a partir del feature
defineFeature(feature, (test) => {
  let response: APIGatewayProxyResult;
  let event: any;

  test("Éxito al guardar un planeta válido", ({ given, when, then, and }) => {
    // Background: el endpoint está disponible
    given("que el endpoint POST /almacenar está disponible", () => {
      // Comprobamos que el handler exista
      expect(handler).toBeDefined();
    });

    // Paso: cuerpo válido
    given(
      'un body válido con id "custom1", planetName "Test Planet" y climate "temperate"',
      () => {
        event = {
          body: JSON.stringify({
            id: "custom1",
            planetName: "Test Planet",
            climate: "temperate",
          }),
        };
      }
    );

    // Acción: invocar al handler
    when("hago una petición al handler de almacenar", async () => {
      response = (await handler(
        event as any,
        {} as any,
        () => {}
      )) as APIGatewayProxyResult;
    });

    // Aserciones sobre el resultado
    then("recibo un statusCode 201", () => {
      expect(response.statusCode).toBe(201);
    });

    and('la respuesta contiene "Planeta almacenado correctamente"', () => {
      const body = JSON.parse(response.body);
      expect(body.message).toBe("Planeta almacenado correctamente");
    });

    and('el item almacenado incluye id "custom1"', () => {
      const body = JSON.parse(response.body);
      expect(body.item.id).toBe("custom1");
    });
  });

  test("Petición sin body", ({ given, when, then, and }) => {
    // Background: endpoint disponible
    given("que el endpoint POST /almacenar está disponible", () => {});

    // Paso: body nulo
    given("un body nulo", () => {
      event = { body: null };
    });

    // Acción
    when("hago una petición al handler de almacenar", async () => {
      response = (await handler(
        event as any,
        {} as any,
        () => {}
      )) as APIGatewayProxyResult;
    });

    // Aserciones
    then("recibo un statusCode 400", () => {
      expect(response.statusCode).toBe(400);
    });

    and(
      'la respuesta contiene el error "No se proporcionó cuerpo en la petición"',
      () => {
        const body = JSON.parse(response.body);
        expect(body.error).toBe("No se proporcionó cuerpo en la petición");
      }
    );
  });

  test("Falta el campo id", ({ given, when, then, and }) => {
    // Background: endpoint disponible
    given("que el endpoint POST /almacenar está disponible", () => {});

    // Paso: body sin id
    given(
      'un body con planetName "Tatooine" y climate "arid" pero sin id',
      () => {
        event = {
          body: JSON.stringify({ planetName: "Tatooine", climate: "arid" }),
        };
      }
    );

    // Acción
    when("hago una petición al handler de almacenar", async () => {
      response = (await handler(
        event as any,
        {} as any,
        () => {}
      )) as APIGatewayProxyResult;
    });

    // Aserciones
    then("recibo un statusCode 400", () => {
      expect(response.statusCode).toBe(400);
    });

    and("el mensaje de error contiene 'El campo \"id\" es obligatorio'", () => {
      const body = JSON.parse(response.body);
      expect(body.error).toContain('El campo "id" es obligatorio');
    });
  });
});
