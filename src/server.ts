import { resolve } from "node:path";
import staticPlugin from "@fastify/static";
import { loadConfig } from "./config.js";
import { openDatabase } from "./runtime.js";
import { createServices } from "./services.js";
import { buildApp } from "./app.js";
import { BackgroundJobs } from "./jobs.js";
const config = loadConfig(),
  db = await openDatabase(config);
try {
  const services = await createServices(db, config),
    app = await buildApp(services);
  const jobs = new BackgroundJobs(db, config, services.billing, (event, code) =>
    app.log.error({ event, code }),
  );
  await app.register(staticPlugin, {
    root: resolve(process.cwd(), "web-dist"),
    prefix: "/site/",
    cacheControl: true,
    maxAge: 3600000,
  });
  app.addHook("onClose", async () => {
    await jobs.stop();
    await db.close();
  });
  let closing = false;
  const shutdown = async () => {
    if (closing) return;
    closing = true;
    const timeout = setTimeout(() => process.exit(1), 30000);
    timeout.unref();
    await app.close();
    clearTimeout(timeout);
  };
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);
  await app.listen({ host: config.host, port: config.port });
  jobs.start();
} catch (error) {
  await db.close();
  throw error;
}
