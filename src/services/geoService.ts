// services/geoService.ts
import axios from "axios";

export async function getCoordinates(placeName: string) {
  const url = `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(
    placeName
  )}&format=json&limit=1`;
  const res = await axios.get(url, {
    headers: { "User-Agent": "StarWarsApp/1.0" },
  });
  if (res.data.length === 0) return null;
  return { lat: res.data[0].lat, lon: res.data[0].lon };
}
