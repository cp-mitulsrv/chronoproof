import { test, expect } from "bun:test";
import request from "supertest";
import { buildApp } from "../src/app";

test("GET /health returns ok (no auth, no DB)", async () => {
  const app = buildApp();
  const res = await request(app).get("/health");
  expect(res.status).toBe(200);
  expect(res.body).toEqual({ status: "ok" });
});
