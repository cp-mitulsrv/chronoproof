import { buildApp } from "./app.js";
import config from "./config/index.js";

const app = buildApp();

// App Service injects PORT; the app binds to it.
const server = app.listen(config.port, () => {
  console.log(`ChronoProof listening on port ${config.port}`);
});

export default server;
