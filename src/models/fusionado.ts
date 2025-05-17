export interface Fusionado {
  planetName: string;
  climate: string;
  population: string;
  weather: {
    temperatureC: number;
    description: string;
  };
  timestamp: number;
}
