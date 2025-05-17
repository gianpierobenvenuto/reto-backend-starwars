import { APIGatewayProxyHandler } from "aws-lambda";
import * as fs from "fs";
import * as path from "path";
import * as mime from "mime-types";

const swaggerDistPath = path.join(
  __dirname,
  "../../node_modules/swagger-ui-dist"
);
const openApiPath = path.join(__dirname, "../../openapi.json");

export const handler: APIGatewayProxyHandler = async (event) => {
  const reqPath = event.path || "";

  if (reqPath === "/docs" || reqPath === "/docs/") {
    const indexPath = path.join(swaggerDistPath, "index.html");
    let html = fs.readFileSync(indexPath, "utf8");
    html = html.replace(/url: "https?:\/\/.*?"/, 'url: "./openapi.json"');
    return {
      statusCode: 200,
      headers: { "Content-Type": "text/html" },
      body: html,
    };
  }

  if (reqPath.endsWith("openapi.json")) {
    const openapiJson = fs.readFileSync(openApiPath, "utf8");
    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: openapiJson,
    };
  }

  const relativeAssetPath = reqPath.replace(/^\/docs\//, "");
  const filePath = path.join(swaggerDistPath, relativeAssetPath);

  if (fs.existsSync(filePath)) {
    const fileBuffer = fs.readFileSync(filePath);
    const contentType = mime.lookup(filePath) || "application/octet-stream";
    return {
      statusCode: 200,
      headers: { "Content-Type": contentType },
      body: fileBuffer.toString("base64"),
      isBase64Encoded: true,
    };
  }

  return { statusCode: 404, body: "Not Found" };
};
