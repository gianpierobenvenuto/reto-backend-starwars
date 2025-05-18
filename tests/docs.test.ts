/**
 * @file docs.test.ts
 * @description Pruebas unitarias para el handler `docs`. Verifica que rutas desconocidas devuelvan 404 con mensaje en español.
 * @author Gianpiero Benvenuto
 */

import { handler } from "../src/handlers/docs";
import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";

describe("handler de docs", () => {
  it("debería devolver 404 para rutas desconocidas", async () => {
    // Simular evento con ruta que no existe en /docs
    const event = {
      path: "/docs/unknown-file.js",
    } as APIGatewayProxyEvent;

    // Llamar al handler con el evento simulado
    const result = (await handler(event)) as APIGatewayProxyResult;

    // Verificar código de estado y cuerpo
    expect(result.statusCode).toBe(404);
    expect(result.body).toBe("No encontrado");
  });
});
