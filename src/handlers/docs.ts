import fs from "fs";
import path from "path";
import mime from "mime-types";
import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";

const swaggerDistPath = path.dirname(
  require.resolve("swagger-ui-dist/package.json")
);
const openApiPath = path.join(__dirname, "../../openapi.json");
const STAGE = process.env.STAGE || "dev";
const ROOT = `/${STAGE}/`;

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

export const handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  const reqPath = event.path ?? "";

  if (reqPath === "/docs" || reqPath === "/docs/") {
    const index = path.join(swaggerDistPath, "index.html");
    let html = fs.readFileSync(index, "utf8");

    // Aquí inyectamos un script que inicializa SwaggerUIBundle con tu spec
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

    // Removemos la configuración default para evitar que se cargue la Petstore
    // Por ejemplo, reemplazamos cualquier inicialización default
    html = html.replace(/<script>.*SwaggerUIBundle\(.*\);.*<\/script>/s, "");

    // Insertamos el script justo antes de </body>
    html = html.replace("</body>", `${initScript}</body>`);

    // Ajustar href/src para cargar assets desde la ruta correcta
    html = html.replace(
      /(href|src)="([^"/][^"]*)"/g,
      (_m, attr, file) => `${attr}="${ROOT}${file}"`
    );

    return {
      statusCode: 200,
      headers: { "Content-Type": "text/html" },
      body: html,
    };
  }

  if (reqPath === "/docs/openapi.json") {
    return serveFile(openApiPath);
  }

  if (reqPath.startsWith("/docs/")) {
    const rel = reqPath.replace(/^\/docs\//, "");
    const file = path.join(swaggerDistPath, rel);
    if (fs.existsSync(file)) return serveFile(file);
  }

  const rootRel = reqPath.replace(new RegExp(`^/${STAGE}/`), "");
  const rootFile = path.join(swaggerDistPath, rootRel);
  if (fs.existsSync(rootFile)) return serveFile(rootFile);

  return { statusCode: 404, body: "Not Found" };
};
