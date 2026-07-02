import rateLimit from "express-rate-limit";

// Sliding-window limiter for the sensitive auth endpoints (login/register/refresh).
// In-memory for now; move to a shared store (Redis) before scaling out to
// multiple App Service instances.
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Too many requests, please try again later" },
});
