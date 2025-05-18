Feature: Almacenamiento de planetas personalizados

  Background:
    Given que el endpoint POST /almacenar está disponible

  Scenario: Éxito al guardar un planeta válido
    Given un body válido con id "custom1", planetName "Test Planet" y climate "temperate"
    When hago una petición al handler de almacenar
    Then recibo un statusCode 201
    And la respuesta contiene "Planeta almacenado correctamente"
    And el item almacenado incluye id "custom1"

  Scenario: Petición sin body
    Given un body nulo
    When hago una petición al handler de almacenar
    Then recibo un statusCode 400
    And la respuesta contiene el error "No se proporcionó cuerpo en la petición"

  Scenario: Falta el campo id
    Given un body con planetName "Tatooine" y climate "arid" pero sin id
    When hago una petición al handler de almacenar
    Then recibo un statusCode 400
    And el mensaje de error contiene 'El campo "id" es obligatorio'
