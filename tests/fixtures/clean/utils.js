// Módulo limpio de control: no debe producir ningún hallazgo.

const API_BASE = "https://api.example.com/v1";
const RETRY_LIMIT = 5;

export function sum(a, b) {
  return a + b;
}

export { API_BASE, RETRY_LIMIT };
