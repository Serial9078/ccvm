import axios from "axios";

export const api = axios.create({
  baseURL: "http://192.168.65.199:8088/api/v1",
  timeout: 30000,
});
