import axios from "axios";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "https://secure-chat-1-540z.onrender.com";

export const axiosInstance = axios.create({
	baseURL: `${API_BASE_URL}/api`,
	withCredentials: true,
});
