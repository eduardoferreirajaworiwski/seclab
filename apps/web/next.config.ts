import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Enables the standalone server.js output the Dockerfile copies into the
  // runtime image, instead of requiring a full `node_modules` + `next start`.
  output: "standalone",
};

export default nextConfig;

