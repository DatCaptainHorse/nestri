// @ts-check
import { defineConfig, envField } from 'astro/config';

// https://astro.build/config
export default defineConfig({
    env: {
        schema: {
            WS_AUTH_SECRET: envField.string({ context: "client", access: "public", default: "test-secret-1234" }),
            WS_PORT: envField.number({ context: "client", access: "public", default: 8998 }),
        }
    }
});
