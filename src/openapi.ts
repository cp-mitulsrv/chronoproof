import config from "./config/index.js";

// OpenAPI 3.0 description of the ChronoProof identity hub. Served as JSON at
// /openapi.json and rendered by Swagger UI at /docs.

const openapi = {
  openapi: "3.0.3",
  info: {
    title: "ChronoProof Identity API",
    version: "0.1.0",
    description:
      "Centralized authentication + multi-tenant onboarding for the Chrono product suite. " +
      "Organization = tenant; a tenant owns many workspaces; users hold an org role " +
      "(owner/admin/member) and a per-workspace role (owner/member). ChronoProof signs " +
      "RS256 JWTs verified by the product services via JWKS.",
  },
  servers: [{ url: "/", description: "This server" }],
  tags: [
    { name: "auth", description: "Registration, login, sessions" },
    { name: "workspaces", description: "Workspaces & members" },
    { name: "invitations", description: "Invite & accept" },
    { name: "well-known", description: "Public keys" },
  ],
  components: {
    securitySchemes: {
      bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
    },
    schemas: {
      Error: { type: "object", properties: { message: { type: "string" } } },
      RegisterRequest: {
        type: "object",
        required: ["email", "password", "name", "organizationName"],
        properties: {
          email: { type: "string", format: "email" },
          password: { type: "string", format: "password", minLength: 8 },
          name: { type: "string" },
          organizationName: { type: "string", description: "Creates the tenant" },
          workspaceName: { type: "string", description: "First workspace (default 'Default')" },
        },
      },
      AuthResult: {
        type: "object",
        properties: {
          accessToken: { type: "string", description: "RS256 JWT, ~15 min" },
          user: { $ref: "#/components/schemas/User" },
          workspace: { $ref: "#/components/schemas/WorkspaceRef" },
          role: { type: "string", enum: ["owner", "member"] },
          orgRole: { type: "string", enum: ["owner", "admin", "member"] },
        },
      },
      LoginRequest: {
        type: "object",
        required: ["email", "password"],
        properties: {
          email: { type: "string", format: "email" },
          password: { type: "string", format: "password" },
          workspaceId: {
            type: "string",
            format: "uuid",
            description: "Optional; required when the user is in more than one workspace",
          },
        },
      },
      LoginResult: {
        oneOf: [
          { $ref: "#/components/schemas/AuthResult" },
          {
            type: "object",
            properties: {
              needsWorkspaceSelection: { type: "boolean", enum: [true] },
              workspaces: { type: "array", items: { $ref: "#/components/schemas/WorkspaceRef" } },
            },
          },
        ],
      },
      User: {
        type: "object",
        properties: {
          id: { type: "string", format: "uuid" },
          email: { type: "string", format: "email" },
          name: { type: "string" },
        },
      },
      WorkspaceRef: {
        type: "object",
        properties: { id: { type: "string", format: "uuid" }, name: { type: "string" } },
      },
      Workspace: {
        type: "object",
        properties: {
          id: { type: "string", format: "uuid" },
          name: { type: "string" },
          tenantId: { type: "string", format: "uuid" },
          role: { type: "string", enum: ["owner", "member"] },
        },
      },
      Member: {
        type: "object",
        properties: {
          id: { type: "string", format: "uuid" },
          email: { type: "string", format: "email" },
          name: { type: "string" },
          role: { type: "string", enum: ["owner", "member"] },
        },
      },
      InviteRequest: {
        type: "object",
        required: ["email", "role"],
        properties: {
          email: { type: "string", format: "email" },
          role: { type: "string", enum: ["owner", "member"] },
        },
      },
      AcceptRequest: {
        type: "object",
        required: ["token"],
        properties: {
          token: { type: "string" },
          name: { type: "string", description: "Required if the invitee has no account yet" },
          password: { type: "string", format: "password", description: "Required if new" },
        },
      },
    },
  },
  paths: {
    "/health": {
      get: { tags: ["well-known"], summary: "Health check", responses: { 200: { description: "OK" } } },
    },
    "/.well-known/jwks.json": {
      get: {
        tags: ["well-known"],
        summary: "Public signing keys (JWKS) — how services verify tokens",
        responses: { 200: { description: "JWK Set" } },
      },
    },
    "/auth/register": {
      post: {
        tags: ["auth"],
        summary: "Register — creates user + organization(tenant) + first workspace; caller becomes OWNER",
        requestBody: {
          required: true,
          content: { "application/json": { schema: { $ref: "#/components/schemas/RegisterRequest" } } },
        },
        responses: {
          201: {
            description: "Created; sets httpOnly refresh cookie",
            content: { "application/json": { schema: { $ref: "#/components/schemas/AuthResult" } } },
          },
          400: { description: "Missing fields", content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } } },
          409: { description: "Email already registered", content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } } },
        },
      },
    },
    "/auth/login": {
      post: {
        tags: ["auth"],
        summary: "Login — returns tokens, or a workspace-selection prompt when the user is in >1 workspace",
        requestBody: {
          required: true,
          content: { "application/json": { schema: { $ref: "#/components/schemas/LoginRequest" } } },
        },
        responses: {
          200: { description: "Authenticated or needs selection", content: { "application/json": { schema: { $ref: "#/components/schemas/LoginResult" } } } },
          401: { description: "Bad credentials", content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } } },
        },
      },
    },
    "/auth/token/refresh": {
      post: {
        tags: ["auth"],
        summary: "Rotate the refresh cookie and issue a new access token",
        responses: { 200: { description: "New access token" }, 401: { description: "Invalid/expired session" } },
      },
    },
    "/auth/switch-workspace": {
      post: {
        tags: ["auth"],
        security: [{ bearerAuth: [] }],
        summary: "Switch the active workspace (must be a member) and re-issue the access token",
        requestBody: {
          required: true,
          content: { "application/json": { schema: { type: "object", required: ["workspaceId"], properties: { workspaceId: { type: "string", format: "uuid" } } } } },
        },
        responses: { 200: { description: "New access token" }, 403: { description: "Not a member" } },
      },
    },
    "/auth/logout": {
      post: { tags: ["auth"], security: [{ bearerAuth: [] }], summary: "Revoke the current session", responses: { 200: { description: "OK" } } },
    },
    "/auth/logout-all": {
      post: { tags: ["auth"], security: [{ bearerAuth: [] }], summary: "Revoke all of the user's sessions", responses: { 200: { description: "OK" } } },
    },
    "/workspaces": {
      get: {
        tags: ["workspaces"],
        security: [{ bearerAuth: [] }],
        summary: "List the caller's workspaces",
        responses: { 200: { description: "Workspaces", content: { "application/json": { schema: { type: "object", properties: { workspaces: { type: "array", items: { $ref: "#/components/schemas/Workspace" } } } } } } } },
      },
      post: {
        tags: ["workspaces"],
        security: [{ bearerAuth: [] }],
        summary: "Create a workspace in the caller's org (org owner/admin); caller becomes its owner",
        requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["name"], properties: { name: { type: "string" } } } } } },
        responses: { 201: { description: "Created" }, 403: { description: "Insufficient org role" } },
      },
    },
    "/workspaces/{id}/members": {
      get: {
        tags: ["workspaces"],
        security: [{ bearerAuth: [] }],
        summary: "List members of a workspace the caller belongs to",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
        responses: { 200: { description: "Members", content: { "application/json": { schema: { type: "object", properties: { members: { type: "array", items: { $ref: "#/components/schemas/Member" } } } } } } }, 403: { description: "Not a member" } },
      },
    },
    "/workspaces/{id}/invitations": {
      post: {
        tags: ["invitations"],
        security: [{ bearerAuth: [] }],
        summary: "Invite an email to the active workspace as owner|member (workspace owner only)",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/InviteRequest" } } } },
        responses: { 201: { description: "Invitation created (returns token to deliver)" }, 403: { description: "Not a workspace owner" } },
      },
    },
    "/invitations/accept": {
      post: {
        tags: ["invitations"],
        summary: "Accept an invitation — creates the user if new and joins the workspace as the invited role (member/owner)",
        requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/AcceptRequest" } } } },
        responses: { 200: { description: "Joined" }, 400: { description: "Invalid/expired invite or missing new-user fields" } },
      },
    },
  },
};

// reflect the configured issuer/audience in the description for clarity
const openapiWithDesc = {
  ...openapi,
  info: {
    ...openapi.info,
    description: openapi.info.description + `\n\nissuer: ${config.issuer} · audience: ${config.audience}`,
  },
};

export default openapiWithDesc;
