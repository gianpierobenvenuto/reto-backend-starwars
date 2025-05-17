import axios from "axios";

const BASE_URL = "https://swapi.py4e.com/api";

export async function getPlanet(name: string) {
  const response = await axios.get(`${BASE_URL}/planets/?search=${name}`);
  const planet = response.data.results[0];
  if (!planet) throw new Error("Planeta no encontrado en SWAPI");
  return {
    name: planet.name,
    climate: planet.climate,
    population: planet.population,
  };
}
