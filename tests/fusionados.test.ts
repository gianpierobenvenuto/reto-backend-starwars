/**
 * @file fusionados.test.ts
 * @description Pruebas unitarias para el handler `fusionados`. Verifica el flujo completo:
 *              - Autenticación JWT mockeada
 *              - Sin resultado en caché
 *              - Consulta a SWAPI y servicio de clima mockeados
 *              - Respuesta 200 con datos fusionados
 * @author Gianpiero Benvenuto
 */

import { handler } from "../src/handlers/fusionados";
import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
  Callback,
} from "aws-lambda";
import * as swapiService from "../src/services/swapiService";
import * as weatherService from "../src/services/weatherService";
import * as cacheService from "../src/services/cacheService";

// Mock de verifyToken para simular siempre autenticación válida
jest.mock("../src/utils/auth", () => ({
  verifyToken: () => ({ valid: true, payload: { userId: "test" } }),
}));

// Mock de los servicios externos para no hacer llamadas de red ni a DynamoDB
jest.mock("../src/services/swapiService");
jest.mock("../src/services/weatherService");
jest.mock("../src/services/cacheService");

describe("handler de fusionados", () => {
  beforeAll(() => {
    // Definimos la respuesta ficticia de SWAPI
    (swapiService.getPlanet as jest.Mock).mockResolvedValue({
      name: "Tatooine",
      climate: "arid",
      population: "200000",
    });

    // Definimos la respuesta ficticia del servicio de clima
    (weatherService.getWeatherByLatLon as jest.Mock).mockResolvedValue({
      temperatureC: 35,
      description: "clear sky",
    });

    // Forzamos que no exista un item en caché
    (cacheService.getCachedFusionado as jest.Mock).mockResolvedValue(null);
    // Y que cacheFusionado no retorne error
    (cacheService.cacheFusionado as jest.Mock).mockResolvedValue(undefined);
  });

  it("debería devolver datos desde el endpoint /fusionados", async () => {
    // Preparamos un evento válido con el parámetro 'planeta'
    const event = {
      path: "/fusionados",
      httpMethod: "GET",
      queryStringParameters: { planeta: "tatooine" },
      headers: {}, // verifyToken está mockeado, no importa su contenido
    } as unknown as APIGatewayProxyEvent;

    // Simulamos context y callback vacíos para cumplir la firma
    const context = {} as Context;
    const callback = (() => {}) as Callback<APIGatewayProxyResult>;

    // Llamamos al handler con los tres argumentos
    const result = (await handler(
      event,
      context,
      callback
    )) as APIGatewayProxyResult;
    const body = JSON.parse(result.body);

    // Verificamos que sea HTTP 200 OK
    expect(result.statusCode).toBe(200);
    // La respuesta debe contener la propiedad `data`
    expect(body).toHaveProperty("data");
    // Y dentro de data, el nombre del planeta
    expect(body.data).toHaveProperty("planetName", "Tatooine");
    // Además debe indicar la fuente como "live"
    expect(body).toHaveProperty("source", "live");
  });
});
