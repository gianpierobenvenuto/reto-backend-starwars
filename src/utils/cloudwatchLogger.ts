import { CloudWatchLogs } from "@aws-sdk/client-cloudwatch-logs";

// Crear una instancia del cliente de CloudWatch
const cloudWatchLogs = new CloudWatchLogs({});

/**
 * Función para enviar logs a CloudWatch.
 * @param message Mensaje a registrar en el log
 * @param level Nivel de log (por defecto: 'INFO')
 */
export const logToCloudWatch = async (
  message: string,
  level: string = "INFO"
) => {
  const logGroupName = process.env.CLOUDWATCH_LOG_GROUP;
  const logStreamName = process.env.CLOUDWATCH_LOG_STREAM;

  const logEvent = {
    logGroupName,
    logStreamName,
    logEvents: [
      {
        message: `${level}: ${message}`,
        timestamp: Date.now(),
      },
    ],
  };

  try {
    await cloudWatchLogs.putLogEvents(logEvent);
    console.log(`Log enviado a CloudWatch: ${message}`);
  } catch (error) {
    console.error("Error al registrar el log en CloudWatch:", error);
  }
};
