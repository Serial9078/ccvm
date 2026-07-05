import axios from 'axios';

export const api = axios.create({
  baseURL: `http://${window.location.hostname}:8088/api/v1`,
});
