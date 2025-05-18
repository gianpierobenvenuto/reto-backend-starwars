module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",

  // Extensiones de archivo que Jest debería reconocer:
  moduleFileExtensions: ["ts", "js", "json", "feature"],

  // Sólo tus archivos *.bdd.ts
  testMatch: ["**/tests/**/*.bdd.ts"],

  // cómo transformar TS: nada más ts-jest
  transform: {
    "^.+\\.ts$": "ts-jest",
  },
};
