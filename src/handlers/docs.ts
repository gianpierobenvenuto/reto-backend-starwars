/**
 * @file docs.ts
 * @description Lambda handler para servir la documentación Swagger UI de forma estática y dinámica.
 *              Permite acceder a /docs/ y cargar los assets de swagger-ui-dist y el archivo openapi.json.
 * @author Gianpiero Benvenuto
 */

import fs from "fs";
import path from "path";
import mime from "mime-types";
import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { logToCloudWatch } from "../utils/cloudwatchLogger"; // Importa el logger

// Ruta base de la distribución de swagger-ui-dist
const swaggerDistPath = path.dirname(
  require.resolve("swagger-ui-dist/package.json")
);

// Ruta absoluta al archivo OpenAPI generado
const openApiPath = path.join(__dirname, "../../openapi.json");

// Determina el stage de despliegue (por defecto "dev")
const STAGE = process.env.STAGE || "dev";

// Prefijo de ruta para API Gateway en ese stage
const ROOT = `/${STAGE}/`;

/**
 * Sirve un archivo estático desde el sistema de archivos local.
 * Determina automáticamente el tipo MIME y si el contenido debe codificarse en base64.
 */
function serveFile(abs: string): APIGatewayProxyResult {
  const buf = fs.readFileSync(abs);
  const type = (mime.lookup(abs) || "application/octet-stream").toString();

  const isText =
    type.startsWith("text/") ||
    type === "application/javascript" ||
    type === "application/json";

  return {
    statusCode: 200,
    headers: { "Content-Type": type },
    body: isText ? buf.toString("utf8") : buf.toString("base64"),
    ...(isText ? {} : { isBase64Encoded: true }),
  };
}

/**
 * Lambda principal para servir Swagger UI en el endpoint /docs.
 * También maneja la ruta /docs/openapi.json y otros archivos estáticos de Swagger.
 */
export const handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  const reqPath = event.path ?? "";

  // Log de la ruta solicitada
  await logToCloudWatch(`Ruta solicitada: ${reqPath}`, "INFO");

  // Ruta principal /docs o /docs/
  if (reqPath === "/docs" || reqPath === "/docs/") {
    const index = path.join(swaggerDistPath, "index.html");
    let html = fs.readFileSync(index, "utf8");

    // Script de inicialización personalizado para cargar nuestro openapi.json
    const initScript = `
<script>
window.onload = function() {
  if(window.ui) window.ui = null;
  const ui = SwaggerUIBundle({
    url: "${ROOT}docs/openapi.json",
    dom_id: '#swagger-ui',
    presets: [
      SwaggerUIBundle.presets.apis,
      SwaggerUIStandalonePreset
    ],
    layout: "StandaloneLayout"
  });
  window.ui = ui;
};
</script>
    `;

    // Elimina cualquier script de inicialización por defecto (como Petstore)
    html = html.replace(/<script>.*SwaggerUIBundle\(.*\);.*<\/script>/s, "");

    // Inyecta nuestro script justo antes del cierre de </body>
    html = html.replace("</body>", `${initScript}</body>`);

    // Ajusta href/src relativos para que funcionen bajo /{stage}/docs/
    html = html.replace(
      /(href|src)="([^"/][^"]*)"/g,
      (_m, attr, file) => `${attr}="${ROOT}${file}"`
    );

    // Log de respuesta generada para /docs
    await logToCloudWatch("Respuesta generada para /docs", "INFO");

    return {
      statusCode: 200,
      headers: { "Content-Type": "text/html" },
      body: html,
    };
  }

  // Ruta específica para servir el archivo openapi.json
  if (reqPath === "/docs/openapi.json") {
    await logToCloudWatch("Solicitud recibida para openapi.json", "INFO");
    return serveFile(openApiPath);
  }

  // Rutas para los assets de swagger-ui-dist (CSS, JS, etc.)
  if (reqPath.startsWith("/docs/")) {
    const rel = reqPath.replace(/^\/docs\//, "");
    const file = path.join(swaggerDistPath, rel);
    if (fs.existsSync(file)) {
      await logToCloudWatch(`Archivo estático encontrado: ${file}`, "INFO");
      return serveFile(file);
    }
  }

  // Compatibilidad con carga relativa desde la raíz del stage
  const rootRel = reqPath.replace(new RegExp(`^/${STAGE}/`), "");
  const rootFile = path.join(swaggerDistPath, rootRel);
  if (fs.existsSync(rootFile)) {
    await logToCloudWatch(`Archivo estático encontrado: ${rootFile}`, "INFO");
    return serveFile(rootFile);
  }

  // Si no se encontró el archivo o ruta, retornar 404
  await logToCloudWatch(`Ruta no encontrada: ${reqPath}`, "ERROR");

  return { statusCode: 404, body: "No encontrado" };
};
