/**
 * @file geoService.ts
 * @description Servicio para obtener coordenadas geográficas a partir de nombres de lugares
 *              usando la API pública de Nominatim (OpenStreetMap).
 *              Utilizado como paso intermedio para obtener el clima de un planeta por su nombre.
 * @author Gianpiero Benvenuto
 */

import axios from "axios";

/**
 * Consulta la API de Nominatim para obtener las coordenadas (latitud y longitud)
 * de un lugar dado, por ejemplo: "Tatooine".
 *
 * @param placeName Nombre del planeta o lugar a buscar
 * @returns Un objeto con `{ lat, lon }` como strings o `null` si no se encuentra
 */
export async function getCoordinates(placeName: string) {
  const url = `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(
    placeName
  )}&format=json&limit=1`;

  const res = await axios.get(url, {
    headers: { "User-Agent": "StarWarsApp/1.0" }, // requerido por Nominatim
  });

  if (res.data.length === 0) return null;

  return { lat: res.data[0].lat, lon: res.data[0].lon };
}
