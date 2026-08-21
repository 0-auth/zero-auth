import { defineConfig } from "vitepress";

export default defineConfig({
  base: process.env.DOCS_BASE ?? "/v1/",
  title: "zero-auth",
  description: "Developer-first authentication for Node.js APIs",
  sitemap: process.env.DOCS_SITE_URL
    ? { hostname: process.env.DOCS_SITE_URL }
    : undefined,
  transformHead({ pageData }) {
    const siteUrl = process.env.DOCS_SITE_URL;
    if (!siteUrl) return [];

    const pagePath = pageData.relativePath
      .replace(/\.md$/, "")
      .replace(/index$/, "");
    const base = process.env.DOCS_BASE ?? "/v1/";
    const canonical = new URL(`${base}${pagePath}`, siteUrl).toString();

    return [["link", { rel: "canonical", href: canonical }]];
  },
  themeConfig: {
    nav: [
      { text: "v1", link: "/" },
      { text: "Guide", link: "/" },
      { text: "API Reference", link: "/api/" },
      { text: "GitHub", link: "https://github.com/0-auth/zero-auth" },
    ],
    sidebar: {
      "/": [
        {
          text: "Get started",
          items: [
            { text: "Overview", link: "/" },
            { text: "Quick start", link: "/quick-start" },
            { text: "Runnable REST example", link: "/examples/rest-api" },
          ],
        },
        {
          text: "Guides",
          items: [
            { text: "Bearer tokens", link: "/guides/bearer-tokens" },
            { text: "HTTP-only cookies", link: "/guides/cookies" },
            { text: "RBAC and optional auth", link: "/guides/access-control" },
            { text: "Refresh token rotation", link: "/guides/refresh-rotation" },
          ],
        },
        { text: "Configuration", link: "/configuration" },
        { text: "Deployment", link: "/deployment" },
        { text: "Testing", link: "/testing" },
        { text: "Versioning and migrations", link: "/versioning" },
        { text: "FAQ and troubleshooting", link: "/faq" },
        { text: "Security checklist", link: "/security" },
        { text: "Client examples", link: "/clients" },
        { text: "Error reference", link: "/errors" },
        { text: "API Reference", items: [{ text: "Overview", link: "/api/" }] },
      ],
      "/api/": [{ text: "API Reference", link: "/api/" }],
    },
    search: { provider: "local" },
  },
});
