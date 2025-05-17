import * as swapiService from "../src/services/swapiService";
import * as weatherService from "../src/services/weatherService";
import * as cacheService from "../src/services/cacheService";

jest.mock("../src/services/swapiService");
jest.mock("../src/services/weatherService");
jest.mock("../src/services/cacheService");

describe("fusionados handler", () => {
  beforeAll(() => {
    // Definir valores mock para los servicios
    (swapiService.getPlanet as jest.Mock).mockResolvedValue({
      name: "Tatooine",
      climate: "arid",
      population: "200000",
    });

    (weatherService.getWeather as jest.Mock).mockResolvedValue({
      temperatureC: 35,
      description: "clear sky",
    });

    (cacheService.getCachedFusionado as jest.Mock).mockResolvedValue(null);
    (cacheService.cacheFusionado as jest.Mock).mockResolvedValue(undefined);
  });

  it("should return data from fusionados endpoint", async () => {
    const event = {
      queryStringParameters: {
        planet: "tatooine",
      },
    } as any;

    const context = {} as any;
    const callback = () => {};

    const result = await require("../src/handlers/fusionados").handler(
      event,
      context,
      callback
    );
    const body = JSON.parse(result.body);

    expect(result.statusCode).toBe(200);
    expect(body).toHaveProperty("data");
    expect(body.data).toHaveProperty("planetName", "Tatooine");
    expect(body).toHaveProperty("source");
  });
});
