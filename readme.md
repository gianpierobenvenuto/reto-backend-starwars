# Reto Técnico Backend – API Star Wars con AWS Serverless

Este proyecto fue desarrollado como parte de un reto técnico para la posición de Backend Developer. Consiste en una API RESTful desarrollada con Node.js y TypeScript, desplegada en AWS Lambda utilizando el Serverless Framework.

La API integra datos de la Star Wars API (SWAPI) y una API meteorológica para producir un modelo de datos combinado. La solución incluye autenticación con JSON Web Tokens (JWT), persistencia en DynamoDB, cacheo de datos, documentación técnica con OpenAPI, y pruebas automatizadas.

## Desarrollador

Gianpiero Benvenuto
<[GitHub](https://github.com/gianpierobenvenuto)>

## Descripción General

Esta API permite consultar información combinada entre un planeta del universo Star Wars y condiciones meteorológicas simuladas, almacenar manualmente planetas personalizados con su clima asociado, y consultar el historial de combinaciones previamente generadas. La arquitectura está basada en componentes serverless de AWS, incluyendo funciones Lambda, API Gateway, DynamoDB, y Serverless Framework para la definición de infraestructura como código.

## Endpoints

GET /fusionados: Consulta datos desde SWAPI y una API de clima, y los fusiona en una sola respuesta. Acepta como parámetro de consulta `planeta` (string, requerido), correspondiente al nombre del planeta. Requiere token JWT válido en el encabezado de autorización. Si la consulta fue realizada en los últimos 30 minutos, se retorna el resultado desde el sistema de cacheo en DynamoDB. La respuesta contiene un objeto combinado con información del planeta y el clima correspondiente.

POST /almacenar: Permite almacenar un planeta personalizado con datos ingresados manualmente, junto con el clima correspondiente obtenido por nombre. Requiere un cuerpo JSON con los campos `id` (string, requerido), `planetName` (string, requerido), `climate` (string, requerido), y `population` (string, opcional). Este endpoint también requiere token JWT válido.

GET /historial: Retorna el historial de todas las respuestas generadas previamente por el endpoint `/fusionados`. Este endpoint también requiere autenticación con JWT. La respuesta está ordenada en orden cronológico inverso (más recientes primero) y admite paginación.

## Configuración del archivo `.env`

Para que el proyecto funcione correctamente, es necesario crear un archivo `.env` en la raíz del proyecto. Este archivo debe contener las siguientes variables de entorno.

### Pasos para crear el archivo `.env`:

1. Crea un archivo llamado `.env` en la raíz del proyecto.
2. Agrega las siguientes variables de entorno dentro de este archivo:

```dotenv
CLOUDWATCH_LOG_GROUP=tu_log_group_aqui
CLOUDWATCH_LOG_STREAM=tu_log_stream_aqui
DYNAMO_TABLE=reto-backend-starwars-${opt:stage, 'dev'}-fusionadosTable
WEATHER_API_KEY=tu_clave_api_aqui
JWT_SECRET=tu_secreto_jwt_aqui
```

## Autenticación

Este proyecto utiliza autenticación mediante JSON Web Tokens (JWT). Todos los endpoints protegidos requieren incluir el token en el encabezado de autorización. La lógica de validación del token se encuentra implementada en `utils/auth.ts`.

**Token de ejemplo para pruebas**: Para realizar pruebas en la API mediante Swagger UI, puedes utilizar el siguiente token JWT de ejemplo:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJ0ZXN0LXVzZXIiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3NDc1MzM2Mjl9.998nuhaNHvaYuYWmAmxMCED3EkDRQGwOTl8MhW2BVWk
```

También es posible generar un nuevo token JWT ejecutando el archivo `generate-token.js` ubicado en la raíz del proyecto:

```
node generate-token.js
```

## Stack Tecnológico

- Node.js v20: Entorno de ejecución de JavaScript.
- TypeScript: Superset de JavaScript que agrega tipado estático.
- AWS Lambda: Funciones serverless para ejecutar el backend.
- AWS API Gateway: Exposición de endpoints HTTP para interacción con la API.
- AWS DynamoDB: Base de datos NoSQL para persistencia de datos.
- Serverless Framework: Herramienta para gestionar funciones serverless y recursos en AWS.
- Jest: Framework de pruebas unitarias e integración.
- OpenAPI 3.0: Documentación técnica de la API.
- JWT: Autenticación mediante JSON Web Tokens.
- AWS SDK v3: Cliente de AWS optimizado y modularizado.
- Zod: Biblioteca para validación de esquemas y parámetros.
- Axios: Cliente HTTP para hacer peticiones a servicios externos.

## Acceso a la API (Demo)

No es necesario ejecutar ni instalar el proyecto localmente. Toda la API se encuentra desplegada y puede ser utilizada directamente a través del entorno público expuesto mediante Swagger UI.

Acceda a la documentación interactiva y pruebe todos los endpoints a través del siguiente enlace:

[https://pi6undhnwe.execute-api.us-east-1.amazonaws.com/dev/docs/](https://pi6undhnwe.execute-api.us-east-1.amazonaws.com/dev/docs/)

Puede utilizar el token JWT de ejemplo proporcionado anteriormente para autenticar las solicitudes.

## Licencia

Este repositorio fue desarrollado exclusivamente como parte de un proceso de evaluación técnica. Su uso está limitado a fines de demostración y educativos, salvo autorización expresa del autor.
