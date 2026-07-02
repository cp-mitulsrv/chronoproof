import express from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import swaggerUi from "swagger-ui-express";
import config from "./config/index.js";
import openapi from "./openapi.js";
import { authLimiter } from "./middleware/rateLimiter.js";
import { router as wellKnownRouter } from "./jwks/wellKnown.js";
import authRouter from "./routes/auth.js";
import workspacesRouter from "./routes/workspaces.js";
import invitationsRouter from "./routes/invitations.js";
import type { Request, Response, NextFunction } from "express";

export function buildApp() {
  const app = express();
  app.set("trust proxy", 1); // App Service sits behind a proxy; needed for req.ip / secure cookies

  app.use(helmet());
  // CORS: "*" in CORS_ALLOWED_ORIGINS allows ALL origins. Because credentials
  // (the refresh cookie) are used, we reflect the request origin (origin: true)
  // rather than a literal "*" — the spec forbids "*" with credentials.
  const allowAllCors = config.corsAllowedOrigins.includes("*");
  app.use(
    cors({
      origin: allowAllCors ? true : config.corsAllowedOrigins.length ? config.corsAllowedOrigins : false,
      credentials: true,
    })
  );
  app.use(express.json());
  app.use(cookieParser());

  // Public (no auth): health, JWKS, API docs.
  app.get("/health", (req: Request, res: Response) => res.json({ status: "ok" }));
  app.use("/", wellKnownRouter);
  app.get("/openapi.json", (req: Request, res: Response) => res.json(openapi));
  app.use("/docs", swaggerUi.serve, swaggerUi.setup(openapi));

  // Auth + onboarding. Rate-limit the sensitive entry points.
  app.use("/auth/register", authLimiter);
  app.use("/auth/login", authLimiter);
  app.use("/auth/token/refresh", authLimiter);
  app.use("/auth", authRouter);

  // Workspaces & members; invitations (invite + accept).
  app.use("/workspaces", workspacesRouter);
  app.use("/", invitationsRouter);

  // JSON 404 + centralized error handler.
  app.use((req: Request, res: Response) => res.status(404).json({ message: "Not found" }));
  app.use((err: unknown, req: Request, res: Response, next: NextFunction) => {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  });

  return app;
}
