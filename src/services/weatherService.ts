import axios from "axios";

const API_KEY = process.env.WEATHER_API_KEY || "";

export async function getWeather(city: string) {
  const response = await axios.get(
    `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(
      city
    )}&appid=${API_KEY}&units=metric`
  );
  const data = response.data;
  return {
    temperatureC: data.main.temp,
    description: data.weather[0].description,
  };
}

// Nueva función para consultar por latitud y longitud
export async function getWeatherByLatLon(
  lat: string | number,
  lon: string | number
) {
  const response = await axios.get(
    `https://api.openweathermap.org/data/2.5/weather?lat=${lat}&lon=${lon}&appid=${API_KEY}&units=metric`
  );
  const data = response.data;
  return {
    temperatureC: data.main.temp,
    description: data.weather[0].description,
  };
}
