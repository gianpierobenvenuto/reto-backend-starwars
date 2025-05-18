/**
 * @file docs.bdd.ts
 * @description Pruebas BDD para el handler GET /docs y rutas asociadas (openapi.json, assets).
 *              Usa jest-cucumber para mapear los escenarios Gherkin a step definitions.
 * @author Gianpiero Benvenuto
 */
import { defineFeature, loadFeature } from "jest-cucumber";
import { resolve } from "path";
import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { handler } from "../src/handlers/docs";

// Carga el feature
const feature = loadFeature(resolve(__dirname, "../features/docs.feature"));

// Mock del logger para evitar llamadas reales
jest.mock("../src/utils/cloudwatchLogger", () => ({
  logToCloudWatch: jest.fn().mockResolvedValue(undefined),
}));

defineFeature(feature, (test) => {
  let response: APIGatewayProxyResult;
  let event: APIGatewayProxyEvent;

  test("Acceso al endpoint /docs", ({ given, when, then, and }) => {
    given('el endpoint GET "/docs" está disponible', () => {
      expect(handler).toBeDefined();
    });

    when('hago una petición al handler con path "/docs"', async () => {
      event = { path: "/docs" } as any;
      response = await handler(event);
    });

    then("recibo un statusCode 200", () => {
      expect(response.statusCode).toBe(200);
    });

    and(
      'la respuesta tiene header "Content-Type" con valor "text/html"',
      () => {
        expect(response.headers!["Content-Type"]).toBe("text/html");
      }
    );

    and('el body contiene "<!DOCTYPE html>"', () => {
      expect(response.body).toContain("<!DOCTYPE html>");
    });
  });

  test("Acceso al endpoint /docs/openapi.json", ({
    given,
    when,
    then,
    and,
  }) => {
    given('el endpoint GET "/docs/openapi.json" está disponible', () => {
      expect(handler).toBeDefined();
    });

    when(
      'hago una petición al handler con path "/docs/openapi.json"',
      async () => {
        event = { path: "/docs/openapi.json" } as any;
        response = await handler(event);
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

    and('el body contiene "{"', () => {
      expect(response.body.trimStart()).toContain("{");
    });
  });

  test("Acceso a un asset estático de swagger-ui-dist", ({
    given,
    when,
    then,
    and,
  }) => {
    given(
      'existe un asset estático "swagger-ui.css" bajo swagger-ui-dist',
      () => {
        const dist = require.resolve("swagger-ui-dist/package.json");
        const dir = resolve(dist, "..");
        const file = resolve(dir, "swagger-ui.css");
        expect(require("fs").existsSync(file)).toBe(true);
      }
    );

    when(
      'hago una petición al handler con path "/docs/swagger-ui.css"',
      async () => {
        event = { path: "/docs/swagger-ui.css" } as any;
        response = await handler(event);
      }
    );

    then("recibo un statusCode 200", () => {
      expect(response.statusCode).toBe(200);
    });

    and(
      'la respuesta tiene header "Content-Type" que contiene "text/css"',
      () => {
        expect(response.headers!["Content-Type"]).toContain("text/css");
      }
    );

    and("el body no está vacío", () => {
      expect(response.body.length).toBeGreaterThan(0);
    });
  });

  test("Ruta no encontrada", ({ given, when, then, and }) => {
    given('el endpoint GET "/docs/nonexistent.file" está disponible', () => {
      expect(handler).toBeDefined();
    });

    when(
      'hago una petición al handler con path "/docs/nonexistent.file"',
      async () => {
        event = { path: "/docs/nonexistent.file" } as any;
        response = await handler(event);
      }
    );

    then("recibo un statusCode 404", () => {
      expect(response.statusCode).toBe(404);
    });

    and('el body contiene "No encontrado"', () => {
      expect(response.body).toContain("No encontrado");
    });
  });
});
