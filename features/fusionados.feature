Feature: Fusionar datos de planeta y clima

  Scenario: Acceso a los datos fusionados de un planeta desde la caché
    Given el endpoint GET "/fusionados?planeta=Tatooine" está disponible
    When hago una petición al handler con path "/fusionados?planeta=Tatooine"
    Then recibo un statusCode 200
    And la respuesta tiene header "Content-Type" con valor "application/json"
    And el body contiene "Tatooine"
    And el body contiene "climate"

  Scenario: Acceso a los datos fusionados de un planeta sin caché
    Given el endpoint GET "/fusionados?planeta=Tatooine" está disponible
    When hago una petición al handler con path "/fusionados?planeta=Tatooine"
    Then recibo un statusCode 200
    And la respuesta tiene header "Content-Type" con valor "application/json"
    And el body contiene "Tatooine"
    And el body contiene "climate"
    And el body contiene "weather"

  Scenario: Petición con parámetro "planeta" vacío
    Given el endpoint GET "/fusionados" está disponible
    When hago una petición al handler con path "/fusionados?planeta="
    Then recibo un statusCode 400
    And la respuesta contiene "El parámetro 'planeta' es obligatorio"

  Scenario: Petición sin el parámetro "planeta"
    Given el endpoint GET "/fusionados" está disponible
    When hago una petición al handler con path "/fusionados"
    Then recibo un statusCode 400
    And la respuesta contiene "El parámetro 'planeta' es obligatorio"
