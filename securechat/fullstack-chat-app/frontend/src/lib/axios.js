import axios from "axios";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "https://secure-chat-1-540z.onrender.com";

export const axiosInstance = axios.create({
	baseURL: `${API_BASE_URL}/api`,
	withCredentials: true,
	headers: {
		'Content-Type': 'application/json',
	},
});

// Add request interceptor to log cookies
axiosInstance.interceptors.request.use(
	(config) => {
		console.log('Request config:', config);
		return config;
	},
	(error) => {
		return Promise.reject(error);
	}
);

// Add response interceptor to log responses
axiosInstance.interceptors.response.use(
	(response) => {
		console.log('Response received:', response.status, response.config.url);
		return response;
	},
	(error) => {
		console.log('Response error:', error.response?.status, error.config?.url);
		return Promise.reject(error);
	}
);
