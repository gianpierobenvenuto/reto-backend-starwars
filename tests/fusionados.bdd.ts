/**
 * @file fusionados.bdd.ts
 * @description Pruebas BDD para el handler GET /fusionados, que fusiona los datos de un planeta con clima.
 *              Usa jest-cucumber para mapear los escenarios Gherkin a step definitions.
 * @author Gianpiero Benvenuto
 */

import { defineFeature, loadFeature } from "jest-cucumber";
import { resolve } from "path";
import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { handler } from "../src/handlers/fusionados";

// Carga el feature
const feature = loadFeature(
  resolve(__dirname, "../features/fusionados.feature")
);

// Mocks
jest.mock("../src/utils/cloudwatchLogger", () => ({
  logToCloudWatch: jest.fn().mockResolvedValue(undefined),
}));
jest.mock("../src/utils/auth", () => ({
  verifyToken: () => ({ valid: true, payload: { userId: "test" } }),
}));
jest.mock("../src/services/swapiService", () => ({
  getPlanet: jest.fn().mockResolvedValue({
    name: "Tatooine",
    climate: "arid",
    population: "200000",
  }),
}));
jest.mock("../src/services/weatherService", () => ({
  getWeatherByLatLon: jest.fn().mockResolvedValue({
    temperatureC: 25,
    description: "cielo despejado",
  }),
}));
jest.mock("../src/services/cacheService", () => ({
  getCachedFusionado: jest.fn().mockResolvedValue(null),
  cacheFusionado: jest.fn().mockResolvedValue(undefined),
}));

defineFeature(feature, (test) => {
  let response: APIGatewayProxyResult;
  let event: APIGatewayProxyEvent;

  test("Acceso a los datos fusionados de un planeta desde la caché", ({
    given,
    when,
    then,
    and,
  }) => {
    given(
      'el endpoint GET "/fusionados?planeta=Tatooine" está disponible',
      () => {
        expect(handler).toBeDefined();
      }
    );

    when(
      'hago una petición al handler con path "/fusionados?planeta=Tatooine"',
      async () => {
        event = {
          path: "/fusionados",
          queryStringParameters: { planeta: "Tatooine" },
        } as any;
        response = (await handler(
          event,
          {} as any,
          () => {}
        )) as APIGatewayProxyResult;
      }
    );

    then("recibo un statusCode 200", () => {
      expect(response.statusCode).toBe(200);
    });

    and(
      'la respuesta tiene header "Content-Type" con valor "application/json"',
      () => {
        expect(response.headers!["Content-Type"]).toBe("application/json");
      }
    );

    and('el body contiene "Tatooine"', () => {
      expect(response.body).toContain("Tatooine");
    });

    and('el body contiene "climate"', () => {
      expect(response.body).toContain("climate");
    });
  });

  test("Acceso a los datos fusionados de un planeta sin caché", ({
    given,
    when,
    then,
    and,
  }) => {
    given(
      'el endpoint GET "/fusionados?planeta=Tatooine" está disponible',
      () => {
        expect(handler).toBeDefined();
      }
    );

    when(
      'hago una petición al handler con path "/fusionados?planeta=Tatooine"',
      async () => {
        event = {
          path: "/fusionados",
          queryStringParameters: { planeta: "Tatooine" },
        } as any;
        response = (await handler(
          event,
          {} as any,
          () => {}
        )) as APIGatewayProxyResult;
      }
    );

    then("recibo un statusCode 200", () => {
      expect(response.statusCode).toBe(200);
    });

    and(
      'la respuesta tiene header "Content-Type" con valor "application/json"',
      () => {
        expect(response.headers!["Content-Type"]).toBe("application/json");
      }
    );

    and('el body contiene "Tatooine"', () => {
      expect(response.body).toContain("Tatooine");
    });

    and('el body contiene "climate"', () => {
      expect(response.body).toContain("climate");
    });

    and('el body contiene "weather"', () => {
      expect(response.body).toContain("weather");
    });
  });

  test('Petición con parámetro "planeta" vacío', ({
    given,
    when,
    then,
    and,
  }) => {
    given('el endpoint GET "/fusionados" está disponible', () => {
      expect(handler).toBeDefined();
    });

    when(
      'hago una petición al handler con path "/fusionados?planeta="',
      async () => {
        event = {
          path: "/fusionados",
          queryStringParameters: { planeta: "" },
        } as any;
        response = (await handler(
          event,
          {} as any,
          () => {}
        )) as APIGatewayProxyResult;
      }
    );

    then("recibo un statusCode 400", () => {
      expect(response.statusCode).toBe(400);
    });

    and(
      "la respuesta contiene \"El parámetro 'planeta' es obligatorio\"",
      () => {
        const body = JSON.parse(response.body);
        expect(body.error).toContain("El parámetro 'planeta' es obligatorio");
      }
    );
  });

  test('Petición sin el parámetro "planeta"', ({ given, when, then, and }) => {
    given('el endpoint GET "/fusionados" está disponible', () => {
      expect(handler).toBeDefined();
    });

    when('hago una petición al handler con path "/fusionados"', async () => {
      event = {
        path: "/fusionados",
        queryStringParameters: {},
      } as any;
      response = (await handler(
        event,
        {} as any,
        () => {}
      )) as APIGatewayProxyResult;
    });

    then("recibo un statusCode 400", () => {
      expect(response.statusCode).toBe(400);
    });

    and(
      "la respuesta contiene \"El parámetro 'planeta' es obligatorio\"",
      () => {
        const body = JSON.parse(response.body);
        expect(body.error).toContain("El parámetro 'planeta' es obligatorio");
      }
    );
  });
});
