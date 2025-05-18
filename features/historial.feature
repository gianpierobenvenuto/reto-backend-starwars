Feature: Historial de respuestas fusionadas

  Background:
    Given el endpoint GET "/historial" está disponible

  Scenario: Recuperar historial sin parámetros
    When hago una petición al handler con path "/historial"
    Then recibo un statusCode 200
    And la respuesta contiene "items"
    And la respuesta contiene "lastKey"

  Scenario: Recuperar historial con limit personalizado
    When hago una petición al handler con path "/historial?limit=5"
    Then recibo un statusCode 200
    And la respuesta contiene "items"
    And la respuesta contiene "lastKey"

  Scenario: Parámetro limit inválido
    When hago una petición al handler con path "/historial?limit=abc"
    Then recibo un statusCode 400
    And la respuesta contiene "Expected number"
