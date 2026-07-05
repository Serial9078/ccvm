import axios from 'axios';

const host = window.location.hostname;
const fallback = `http://${host}:8088`;

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || fallback,
  timeout: 15000,
});
