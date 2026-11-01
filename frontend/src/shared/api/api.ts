import axios from "axios";

import { apiBaseUrl } from "./config";

export const api = axios.create({
  baseURL: apiBaseUrl,
  timeout: 30000,
});
