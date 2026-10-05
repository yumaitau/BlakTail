import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  poweredByHeader: false,
  // Never publish browser source maps from production builds.
  productionBrowserSourceMaps: false,
  experimental: {
    serverActions: {
      // Server action payloads (forms, ACL JSON) stay small.
      bodySizeLimit: "1mb",
    },
  },
  // Static build assets don't pass through src/proxy.ts; give them the
  // headers that matter for files.
  async headers() {
    return [
      {
        source: "/_next/static/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
        ],
      },
    ];
  },
};

export default nextConfig;
