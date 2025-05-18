Feature: Servir documentación Swagger UI

  Scenario: Acceso al endpoint /docs
    Given el endpoint GET "/docs" está disponible
    When hago una petición al handler con path "/docs"
    Then recibo un statusCode 200
    And la respuesta tiene header "Content-Type" con valor "text/html"
    And el body contiene "<!DOCTYPE html>"

  Scenario: Acceso al endpoint /docs/openapi.json
    Given el endpoint GET "/docs/openapi.json" está disponible
    When hago una petición al handler con path "/docs/openapi.json"
    Then recibo un statusCode 200
    And la respuesta tiene header "Content-Type" con valor "application/json"
    And el body contiene "{"

  Scenario: Acceso a un asset estático de swagger-ui-dist
    Given existe un asset estático "swagger-ui.css" bajo swagger-ui-dist
    When hago una petición al handler con path "/docs/swagger-ui.css"
    Then recibo un statusCode 200
    And la respuesta tiene header "Content-Type" que contiene "text/css"
    And el body no está vacío

  Scenario: Ruta no encontrada
    Given el endpoint GET "/docs/nonexistent.file" está disponible
    When hago una petición al handler con path "/docs/nonexistent.file"
    Then recibo un statusCode 404
    And el body contiene "No encontrado"
