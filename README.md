# 🛡️ Serverless Edge DNS Gateway
[English](README.md) | [Tiếng Việt](README_VN.md)

A secure, high-performance DNS-over-HTTPS (DoH) proxy running on Cloudflare's global Edge via Pages Functions. Optimized for speed, geographic accuracy (ECS), and professional adblocking.

---

## ⚡ Key Features

*   **100% Free Usage**: Fully hosted on the Cloudflare Pages Free Tier with a limit of 100,000 requests per day. Given an average consumption of 200 – 4,000 requests per device daily, a single account can comfortably support 10 – 20 devices (or even 100 – 200 devices with casual usage).
*   **Custom Domain Scaling**: Attach your own domain for a professional, short DNS endpoint. You can spread usage across multiple Cloudflare accounts to multiply your quota (100k per account) while keeping your custom domains.
*   **Smart Adblocking**: Local filtering using professional lists (AdGuard, ABPVN, Bypass-VN, etc.), automatically updated **every hour**.
*   **ECS Geo-Optimization (RFC 7871)**: Injects EDNS Client Subnet (IPv4 `/24`, IPv6 `/48`) to ensure CDNs (Akamai, CloudFront, Fastly, BunnyCDN, Gcore) resolve you to the nearest servers.
*   **Sequential Failover Reliability**: 
    *   **Primary/Fallback**: Tries Cloudflare Gateway primary endpoint first, with automatic failover to a backup endpoint if it fails.
    *   **Geo-Bypass**: Automatically detects geo-blocked results (127.0.0.1) and re-resolves via **Mullvad DNS**.
*   **Early Response Filtering**: Drops unnecessary query types (`ANY`, `AAAA`, `PTR`, `HTTPS`) at the edge to save resources and improve speed.
*   **Private TLD Shield**: Prevents local/internal domain leaks (e.g., `.local`, `.lan`, router logins) by returning `NXDOMAIN` instantly.
*   **DNS Redirection (CNAME Injection)**: Redirects domain A to domain B using a CNAME record. This allows forcing a specific CDN chain or overriding resolution (e.g., Bilibili, TikTok, Medium).
*   **Zero-App Setup**: Native Apple `.mobileconfig` generation and a clean, responsive landing page included.

---

## 🚀 Deployment

### 1. Fork & Setup Actions
1. [Fork this project](../../fork) to your GitHub account.
2. Go to the **Actions** tab in your forked repository and click **I understand my workflows, go ahead and enable them**.
3. Manually select and **Enable** the following workflows: `Update DNS Blocklists` and `Delete old workflow runs`.

### 2. Deploy to Cloudflare Pages
1. Go to [Workers & Pages > Create application > Connect to Git](https://dash.cloudflare.com/?to=/:account/pages/new/provider/github).
2. Connect your GitHub and select the forked repository.
3. **Build Settings**: Leave everything as **default** (no changes needed).
4. Click **Save and Deploy**.

---

## ⚙️ Configuration (`functions/[[path]].js`)

Detailed settings are managed at the top of the [functions/[[path]].js](functions/[[path]].js#L2-L30) file.

### Resolvers & Upstreams
The parameters below are pre-configured with optimal defaults.

> [!IMPORTANT]
> Only **Cloudflare Gateway** ensures the most accurate CDN resolution for services like Akamai. You can use the default upstreams provided, or create your own [DNS locations](https://dash.cloudflare.com/?to=/:account/one/networks/resolvers-proxies) within your Cloudflare account.

| Constant | Default | Description |
| :--- | :--- | :--- |
| `UPSTREAM_PRIMARY` | Cloudflare Gateway | Main resolver URL. |
| `UPSTREAM_FALLBACK` | Cloudflare Gateway | Backup resolver. |
| `UPSTREAM_GEO_BYPASS`| `dns.mullvad.net` | Used when upstream returns loopback (127.0.0.1). |

### Edge Filtering (Optimization)
| Constant | Default | Description |
| :--- | :--- | :--- |
| `BLOCK_AAAA` | `false` | Forces IPv4 routing by blocking AAAA. |
| `BLOCK_HTTPS` | `false` | Prevents Type 65 lookups (speeds up resolution). |
| `BLOCK_ANY` | `false` | Blocks resource-heavy ANY queries. |
| `BLOCK_PTR` | `false` | Blocks reverse DNS queries. |
| `BLOCK_PRIVATE_TLD` | `true` | Blocks internal/router domains. |
| `ECS_INJECTION_ENABLED` | `true` | Enables ECS Injection (Required for accurate CDN). |

---

## 🛠 Rule Management (`rules/`)

Rules are located in the `rules/` folder. When you modify and commit these files on GitHub, Cloudflare Pages will automatically sync and apply the new configuration.

Detailed rules:

*   **`blocklists.txt`** / **`allowlists.txt`**: Automatically updated **every hour**.
    *   **Logic**: Domains in `allowlists.txt` override `blocklists.txt`, ensuring they are never blocked even if flagged by a filter (prevents false positives).
    *   **How to configure**: Edit the URLs in the `curl` command inside [update_lists.sh](update_lists.sh#L34-L43) to add or remove filtering sources.
*   **`private_tlds.txt`**: Add your custom local domains or router URLs here.
*   **`redirect_rules.txt`**: Redirects domain A to domain B using a CNAME record. Perfect for forcing specific CDN results.
    *   **Format**: `source-domain target-domain`
    *   **Example**: `www.bilibili.tv www.bilibili.tv.w.cdngslb.com`
    *   **Effect**: If `www.bilibili.tv` randomly returns multiple CDNs (e.g., GSLB or Akamai), this rule forces it to always use `www.bilibili.tv.w.cdngslb.com`.

---

## 📱 Setup Instructions

### Browsers (Chrome / Edge / Firefox)
1.  Go to **Settings** > **Privacy and Security** > **Security**.
2.  Enable **"Use secure DNS"** and select **"Custom"**.
3.  Paste your endpoint: `https://your-project.pages.dev/dns-query`

### Apple (iOS / macOS)
1.  Open your project URL in **Safari**.
2.  Click **Download Apple Profile** and install via system settings.

### Android (Intra App)
1.  Open Intra > **Configure custom server URL**.
2.  Paste your `/dns-query` endpoint and toggle ON.

---

## 🔎 API & Endpoints

| Endpoint | Description |
| :--- | :--- |
| `/dns-query` | The DoH resolver endpoint. |
| `/debug` | Returns a JSON summary of config, stats, and rule counts. |
| `/apple` | Generates a native Apple `.mobileconfig` profile for iOS/macOS. |

---
