import { create } from "zustand";
import { axiosInstance } from "../lib/axios.js";
import toast from "react-hot-toast";
import { io } from "socket.io-client";
import { useEncryptionStore } from "./useEncryptionStore.js";

const BASE_URL = import.meta.env.MODE === "development" ? "http://localhost:5001" : "https://secure-chat-1-540z.onrender.com";

export const useAuthStore = create((set, get) => ({
  authUser: null,
  authToken: null,
  isSigningUp: false,
  isLoggingIn: false,
  isUpdatingProfile: false,
  isCheckingAuth: true,
  onlineUsers: [],
  socket: null,

  checkAuth: async () => {
    try {
      // Check if we have a stored token
      const storedToken = localStorage.getItem('authToken');
      if (storedToken) {
        window.authToken = storedToken;
        set({ authToken: storedToken });
      }
      
      const res = await axiosInstance.get("/auth/check");

      set({ authUser: res.data });

      // Initialize encryption when auth is checked and wait for it to complete
      await useEncryptionStore.getState().initializeEncryption();

      get().connectSocket();
    } catch (error) {
      console.log("Error in checkAuth:", error);
      set({ authUser: null, authToken: null });
      localStorage.removeItem('authToken');
      window.authToken = null;
    } finally {
      set({ isCheckingAuth: false });
    }
  },

  signup: async (data) => {
    set({ isSigningUp: true });
    try {
      const res = await axiosInstance.post("/auth/signup", data);
      set({ authUser: res.data });

      // Store encryption keys if they were generated during signup
      if (res.data.encryptionKeys) {
        useEncryptionStore.getState().storeKeys(res.data.encryptionKeys);
      }

      toast.success("Account created successfully");
      get().connectSocket();
    } catch (error) {
      toast.error(error.response.data.message);
    } finally {
      set({ isSigningUp: false });
    }
  },

  login: async (data) => {
    set({ isLoggingIn: true });
    try {
      const res = await axiosInstance.post("/auth/login", data);
      console.log("Login response:", res);
      console.log("Login response headers:", res.headers);
      console.log("Cookies in response:", document.cookie);
      
      set({ authUser: res.data, authToken: res.data.token });
      
      // Store token in localStorage for persistence
      if (res.data.token) {
        localStorage.setItem('authToken', res.data.token);
        window.authToken = res.data.token;
      }

      // Wait a moment for the cookie to be set before initializing encryption
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Initialize encryption after successful login and wait for it to complete
      await useEncryptionStore.getState().initializeEncryption();

      // If user doesn't have encryption keys, show notification
      if (!res.data.hasEncryptionKeys) {
        toast("Encryption keys not found. Generate them in Security Settings.", {
          duration: 5000,
          icon: '🔐'
        });
      }

      toast.success("Logged in successfully");

      get().connectSocket();
    } catch (error) {
      console.log("Login error:", error);
      toast.error(error.response.data.message);
    } finally {
      set({ isLoggingIn: false });
    }
  },

  logout: async () => {
    try {
      await axiosInstance.post("/auth/logout");
      set({ authUser: null, authToken: null });
      
      // Clear token from localStorage
      localStorage.removeItem('authToken');
      window.authToken = null;

      // Clear encryption data on logout
      useEncryptionStore.getState().clearEncryptionData();

      toast.success("Logged out successfully");
      get().disconnectSocket();
    } catch (error) {
      toast.error(error.response.data.message);
    }
  },

  updateProfile: async (data) => {
    set({ isUpdatingProfile: true });
    try {
      const res = await axiosInstance.put("/auth/update-profile", data);
      set({ authUser: res.data });
      toast.success("Profile updated successfully");
    } catch (error) {
      console.log("error in update profile:", error);
      toast.error(error.response.data.message);
    } finally {
      set({ isUpdatingProfile: false });
    }
  },

  connectSocket: () => {
    const { authUser } = get();
    if (!authUser || get().socket?.connected) return;

    const socket = io(BASE_URL, {
      query: {
        userId: authUser._id,
      },
    });
    socket.connect();

    set({ socket: socket });

    socket.on("getOnlineUsers", (userIds) => {
      set({ onlineUsers: userIds });
    });
  },
  disconnectSocket: () => {
    if (get().socket?.connected) get().socket.disconnect();
  },
}));
