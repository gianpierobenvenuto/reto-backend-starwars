/**
 * @file geoService.ts
 * @description Servicio para obtener coordenadas geográficas a partir de nombres de lugares
 *              usando la API pública de Nominatim (OpenStreetMap).
 *              Utilizado como paso intermedio para obtener el clima de un planeta por su nombre.
 * @author Gianpiero Benvenuto
 */

import axios from "axios";
import { logToCloudWatch } from "../utils/cloudwatchLogger"; // Importa el logger

/**
 * Consulta la API de Nominatim para obtener las coordenadas (latitud y longitud)
 * de un lugar dado, por ejemplo: "Tatooine".
 *
 * @param placeName Nombre del planeta o lugar a buscar
 * @returns Un objeto con `{ lat, lon }` como strings o `null` si no se encuentra
 */
export async function getCoordinates(placeName: string) {
  // Log de la solicitud de coordenadas
  await logToCloudWatch(
    `Consultando coordenadas para el lugar: ${placeName}`,
    "INFO"
  );

  const url = `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(
    placeName
  )}&format=json&limit=1`;

  try {
    const res = await axios.get(url, {
      headers: { "User-Agent": "StarWarsApp/1.0" }, // requerido por Nominatim
    });

    if (res.data.length === 0) {
      // Log cuando no se encuentran coordenadas
      await logToCloudWatch(
        `No se encontraron coordenadas para el lugar: ${placeName}`,
        "INFO"
      );
      return null;
    }

    // Log de las coordenadas obtenidas
    await logToCloudWatch(
      `Coordenadas encontradas para ${placeName}: lat=${res.data[0].lat}, lon=${res.data[0].lon}`,
      "INFO"
    );

    return { lat: res.data[0].lat, lon: res.data[0].lon };
  } catch (error: unknown) {
    // Verificación del tipo de error
    if (error instanceof Error) {
      // Log de error si la consulta falla
      await logToCloudWatch(
        `Error al consultar coordenadas para ${placeName}: ${error.message}`,
        "ERROR"
      );
    } else {
      // En caso de que el error no sea una instancia de Error, loguear el error desconocido
      await logToCloudWatch(
        `Error desconocido al consultar coordenadas para ${placeName}`,
        "ERROR"
      );
    }
    throw new Error("Error al obtener coordenadas");
  }
}
