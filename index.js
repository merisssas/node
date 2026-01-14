'use strict';

const express = require('express');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawn, execFileSync } = require('node:child_process');
const { Readable } = require('node:stream');
const { pipeline } = require('node:stream/promises');

const app = express();

// =====================
// ENV + DEFAULTS
// =====================
const PORT = Number(process.env.PORT || 3000);

// workspace (default aman: /tmp)
const FILE_PATH = process.env.FILE_PATH || '/tmp/nodejs-paas-proxy';

// IDs (UPDATED HERE)
const UUID = process.env.UUID || 'd342d11e-d424-4583-b36e-524ab1f0afa4';

// Nezha
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';
const NEZHA_PORT = process.env.NEZHA_PORT || '5555';
const NEZHA_KEY = process.env.NEZHA_KEY || '';
const NEZHA_TLS = (process.env.NEZHA_TLS || (NEZHA_PORT === '443' ? '1' : '0')) === '1';

// Cloudflare Tunnel (cloudflared)
const ARGO_AUTH = process.env.ARGO_AUTH || '';      // token OR credentials JSON
const ARGO_DOMAIN = process.env.ARGO_DOMAIN || '';  // untuk mode credentials JSON
const ARGO_TUNNEL_ID = process.env.ARGO_TUNNEL_ID || ''; // untuk mode credentials JSON (UUID tunnel / name)

// “CFIP fronting” optional: isi dengan IP/hostname yang resolve ke Cloudflare anycast
// Default kamu sebelumnya: www.visa.com (biar resolve ke Cloudflare IP)
const CFIP = process.env.CFIP || 'www.visa.com';

// Xray
const XRAY_LISTEN = process.env.XRAY_LISTEN || '127.0.0.1';
const XRAY_VLESS_PORT = Number(process.env.XRAY_VLESS_PORT || 8001);
const XRAY_VMESS_PORT = Number(process.env.XRAY_VMESS_PORT || 8002);
const XRAY_TROJAN_PORT = Number(process.env.XRAY_TROJAN_PORT || 8003);

// Versions (override-able)
const VERSIONS = {
  XRAY: process.env.XRAY_VERSION || 'v25.12.8',
  NEZHA: process.env.NEZHA_AGENT_VERSION || 'v1.14.4',
  CLOUDFLARED: process.env.CLOUDFLARED_VERSION || '2025.11.1'
};

// Optional: mirror base URL (kalau GitHub diblok)
const MIRROR = {
  XRAY_BASE: process.env.XRAY_DOWNLOAD_BASE || 'https://github.com/XTLS/Xray-core/releases/download',
  NEZHA_BASE: process.env.NEZHA_DOWNLOAD_BASE || 'https://github.com/nezhahq/agent/releases/download',
  CLOUDFLARED_BASE: process.env.CLOUDFLARED_DOWNLOAD_BASE || 'https://github.com/cloudflare/cloudflared/releases/download'
};

const START_TS = Date.now();

// =====================
// UTIL
// =====================
function getArch() {
  const a = os.arch();
  if (a === 'x64') return 'amd64';
  if (a === 'arm64') return 'arm64';
  return 'amd64';
}

async function ensureDir(p) {
  await fsp.mkdir(p, { recursive: true });
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function fileExists(p) {
  try {
    await fsp.access(p, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

// download with retries + timeout, streaming to disk
async function downloadToFile(url, dstPath, { mode = 0o755, timeoutMs = 30000, retries = 3 } = {}) {
  await ensureDir(path.dirname(dstPath));

  if (await fileExists(dstPath)) {
    return { path: dstPath, skipped: true };
  }

  const tmpPath = `${dstPath}.tmp.${Date.now()}`;

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(new Error('timeout')), timeoutMs);

      const res = await fetch(url, {
        redirect: 'follow',
        signal: ctrl.signal,
        headers: { 'user-agent': 'nodejs-paas-proxy/2.1' }
      });

      clearTimeout(t);

      if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);

      await pipeline(Readable.fromWeb(res.body), fs.createWriteStream(tmpPath));
      await fsp.chmod(tmpPath, mode);
      await fsp.rename(tmpPath, dstPath);

      return { path: dstPath, skipped: false };
    } catch (e) {
      // cleanup temp
      try { await fsp.rm(tmpPath, { force: true }); } catch {}

      if (attempt === retries) throw e;
      const backoff = 800 * attempt;
      console.log(`[DL] retry ${attempt}/${retries} after ${backoff}ms: ${url} -> ${e.message}`);
      await sleep(backoff);
    }
  }
}

// =====================
// XRAY CONFIG
// =====================
async function generateXrayConfig() {
  const cfg = {
    log: { loglevel: process.env.XRAY_LOGLEVEL || 'none' },
    inbounds: [
      {
        listen: XRAY_LISTEN,
        port: XRAY_VLESS_PORT,
        protocol: 'vless',
        settings: {
          clients: [{ id: UUID }],
          decryption: 'none'
        },
        streamSettings: {
          network: 'ws',
          wsSettings: { path: '/vless' }
        }
      },
      {
        listen: XRAY_LISTEN,
        port: XRAY_VMESS_PORT,
        protocol: 'vmess',
        settings: {
          clients: [{ id: UUID, alterId: 0 }]
        },
        streamSettings: {
          network: 'ws',
          wsSettings: { path: '/vmess' }
        }
      },
      {
        listen: XRAY_LISTEN,
        port: XRAY_TROJAN_PORT,
        protocol: 'trojan',
        settings: {
          clients: [{ password: UUID }]
        },
        streamSettings: {
          network: 'ws',
          wsSettings: { path: '/trojan' }
        }
      }
    ],
    outbounds: [{ protocol: 'freedom' }]
  };

  const cfgPath = path.join(FILE_PATH, 'config.json');
  await fsp.writeFile(cfgPath, JSON.stringify(cfg, null, 2));
  console.log('[XRAY] config.json generated');
  return cfgPath;
}

// =====================
// PROCESS SUPERVISOR
// =====================
class ManagedProcess {
  constructor(name, cmd, args, opts = {}) {
    this.name = name;
    this.cmd = cmd;
    this.args = args;
    this.cwd = opts.cwd || FILE_PATH;
    this.env = opts.env || process.env;
    this.restart = opts.restart !== false;
    this.maxRestarts = Number(opts.maxRestarts ?? 20);
    this.restartCount = 0;
    this.backoffBase = Number(opts.backoffBase ?? 800);
    this.child = null;
    this.lastExit = null;
  }

  start() {
    if (this.child) return;

    console.log(`[PROC] starting ${this.name}: ${this.cmd} ${this.args.join(' ')}`);
    const child = spawn(this.cmd, this.args, {
      cwd: this.cwd,
      env: this.env,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    this.child = child;

    const prefix = (buf) => {
      const s = buf.toString().trimEnd();
      if (!s) return;
      for (const line of s.split('\n')) {
        console.log(`[${this.name}] ${line}`);
      }
    };

    child.stdout.on('data', prefix);
    child.stderr.on('data', prefix);

    child.on('exit', async (code, signal) => {
      this.lastExit = { code, signal, at: Date.now() };
      this.child = null;

      console.log(`[PROC] ${this.name} exited code=${code} signal=${signal}`);

      if (!this.restart) return;
      if (this.restartCount >= this.maxRestarts) {
        console.log(`[PROC] ${this.name} restart limit reached (${this.maxRestarts}). stop restarting.`);
        return;
      }

      this.restartCount++;
      const wait = this.backoffBase * this.restartCount;
      console.log(`[PROC] restarting ${this.name} in ${wait}ms (attempt ${this.restartCount})`);
      await sleep(wait);
      this.start();
    });

    child.on('error', (err) => {
      console.log(`[PROC] ${this.name} spawn error: ${err.message}`);
    });
  }

  stop(sig = 'SIGTERM') {
    if (!this.child) return;
    try {
      console.log(`[PROC] stopping ${this.name} (${sig})`);
      this.child.kill(sig);
    } catch {}
  }

  status() {
    return {
      name: this.name,
      running: !!this.child,
      pid: this.child?.pid || null,
      restartCount: this.restartCount,
      lastExit: this.lastExit
    };
  }
}

const procs = {
  xray: null,
  nezha: null,
  argo: null
};

// =====================
// CLOUDFLARED CONFIG (credentials JSON mode)
// =====================
async function writeCloudflaredConfig({ tunnelId, domain, credsPath }) {
  // Ingress rules boleh match hostname+path; wajib ada catch-all terakhir. 6
  const cfgYml = [
    `tunnel: ${tunnelId}`,
    `credentials-file: ${credsPath}`,
    ``,
    `ingress:`,
    `  - hostname: ${domain}`,
    `    path: /vless`,
    `    service: http://127.0.0.1:${XRAY_VLESS_PORT}`,
    `  - hostname: ${domain}`,
    `    path: /vmess`,
    `    service: http://127.0.0.1:${XRAY_VMESS_PORT}`,
    `  - hostname: ${domain}`,
    `    path: /trojan`,
    `    service: http://127.0.0.1:${XRAY_TROJAN_PORT}`,
    `  - service: http_status:404`,
    ``
  ].join('\n');

  const cfgPath = path.join(FILE_PATH, 'cloudflared-config.yml');
  await fsp.writeFile(cfgPath, cfgYml);
  return cfgPath;
}

// =====================
// MAIN STARTUP
// =====================
async function startServices() {
  const arch = getArch();
  console.log(`[INIT] arch=${arch}`);
  console.log(`[INIT] uuid=${UUID}`);
  console.log(`[INIT] workdir=${FILE_PATH}`);

  await ensureDir(FILE_PATH);

  // ====== URLs (GitHub official)
  const xrayAsset = arch === 'amd64' ? 'Xray-linux-64.zip' : 'Xray-linux-arm64-v8a.zip';
  const xrayUrl = `${MIRROR.XRAY_BASE}/${VERSIONS.XRAY}/${xrayAsset}`;

  const nezhaAsset = `nezha-agent_linux_${arch}.zip`;
  const nezhaUrl = `${MIRROR.NEZHA_BASE}/${VERSIONS.NEZHA}/${nezhaAsset}`;

  const cloudflaredAsset = `cloudflared-linux-${arch}`;
  const cloudflaredUrl = `${MIRROR.CLOUDFLARED_BASE}/${VERSIONS.CLOUDFLARED}/${cloudflaredAsset}`;

  try {
    // ====== 1) Xray
    const xrayZip = path.join(FILE_PATH, 'xray.zip');
    await downloadToFile(xrayUrl, xrayZip, { mode: 0o644, timeoutMs: 45000, retries: 4 });

    execFileSync('unzip', ['-o', xrayZip, '-d', FILE_PATH], { stdio: 'inherit' });
    await fsp.rm(xrayZip, { force: true });

    // Ensure executable
    const xrayBin = path.join(FILE_PATH, 'xray');
    await fsp.chmod(xrayBin, 0o755);

    const cfgPath = await generateXrayConfig();

    procs.xray = new ManagedProcess('XRAY', xrayBin, ['-c', cfgPath], { restart: true });
    procs.xray.start();

    // ====== 2) Nezha (optional)
    if (NEZHA_SERVER && NEZHA_KEY) {
      const nezhaZip = path.join(FILE_PATH, 'nezha.zip');
      await downloadToFile(nezhaUrl, nezhaZip, { mode: 0o644, timeoutMs: 45000, retries: 4 });

      execFileSync('unzip', ['-o', nezhaZip, '-d', FILE_PATH], { stdio: 'inherit' });
      await fsp.rm(nezhaZip, { force: true });

      const nezhaBin = path.join(FILE_PATH, 'nezha-agent');
      await fsp.chmod(nezhaBin, 0o755);

      const args = ['-s', `${NEZHA_SERVER}:${NEZHA_PORT}`, '-p', NEZHA_KEY];
      if (NEZHA_TLS) args.push('--tls');

      procs.nezha = new ManagedProcess('NEZHA', nezhaBin, args, { restart: true });
      procs.nezha.start();
    } else {
      console.log('[NEZHA] disabled (missing NEZHA_SERVER/NEZHA_KEY)');
    }

    // ====== 3) cloudflared
    const cfBin = path.join(FILE_PATH, 'cloudflared');
    await downloadToFile(cloudflaredUrl, cfBin, { mode: 0o755, timeoutMs: 45000, retries: 4 });

    // Mode A: Token
    // Mode B: Credentials JSON (butuh ARGO_TUNNEL_ID + ARGO_DOMAIN)
    // Mode C: Quick Tunnel (paling simple, tapi hanya expose 1 service via --url)
    if (ARGO_AUTH) {
      const isJsonCreds = ARGO_AUTH.includes('TunnelSecret') && ARGO_AUTH.trim().startsWith('{');

      if (isJsonCreds) {
        if (!ARGO_TUNNEL_ID || !ARGO_DOMAIN) {
          console.log('[ARGO] credentials JSON detected, but ARGO_TUNNEL_ID / ARGO_DOMAIN missing -> fallback to quick tunnel');
          procs.argo = new ManagedProcess('ARGO', cfBin, [
            'tunnel',
            '--edge-ip-version', 'auto',
            '--no-autoupdate',
            '--url', `http://127.0.0.1:${XRAY_VLESS_PORT}`
          ]);
          procs.argo.start();
        } else {
          const credsPath = path.join(FILE_PATH, 'tunnel-credentials.json');
          await fsp.writeFile(credsPath, ARGO_AUTH);
          const cfgPath = await writeCloudflaredConfig({ tunnelId: ARGO_TUNNEL_ID, domain: ARGO_DOMAIN, credsPath });

          procs.argo = new ManagedProcess('ARGO', cfBin, [
            'tunnel',
            '--edge-ip-version', 'auto',
            '--no-autoupdate',
            '--config', cfgPath,
            'run'
          ]);
          procs.argo.start();
        }
      } else {
        // token
        procs.argo = new ManagedProcess('ARGO', cfBin, [
          'tunnel',
          '--edge-ip-version', 'auto',
          '--no-autoupdate',
          'run',
          '--token', ARGO_AUTH
        ]);
        procs.argo.start();
      }
    } else {
      console.log('[ARGO] using quick tunnel (TryCloudflare) -> only VLESS port exposed');
      procs.argo = new ManagedProcess('ARGO', cfBin, [
        'tunnel',
        '--edge-ip-version', 'auto',
        '--no-autoupdate',
        '--url', `http://127.0.0.1:${XRAY_VLESS_PORT}`
      ]);
      procs.argo.start();
    }
  } catch (e) {
    console.error('[FATAL] startup failed:', e);
  }
}

// Graceful shutdown
function shutdown() {
  console.log('[SYS] shutdown requested');
  procs.argo?.stop('SIGTERM');
  procs.nezha?.stop('SIGTERM');
  procs.xray?.stop('SIGTERM');

  // hard kill after timeout
  setTimeout(() => {
    procs.argo?.stop('SIGKILL');
    procs.nezha?.stop('SIGKILL');
    procs.xray?.stop('SIGKILL');
    process.exit(0);
  }, 5000).unref();
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// =====================
// HTTP API
// =====================
app.get('/', (req, res) => {
  res.json({
    status: 'Active',
    uptime_s: Math.floor((Date.now() - START_TS) / 1000),
    info: {
      uuid: UUID,
      versions: VERSIONS,
      xray: { listen: XRAY_LISTEN, ports: { vless: XRAY_VLESS_PORT, vmess: XRAY_VMESS_PORT, trojan: XRAY_TROJAN_PORT } },
      nezha: NEZHA_SERVER ? 'enabled' : 'disabled',
      argo: ARGO_AUTH ? 'configured' : 'quick'
    }
  });
});

app.get('/health', (req, res) => {
  const st = {
    ok: true,
    processes: {
      xray: procs.xray?.status() || { running: false },
      nezha: procs.nezha?.status() || { running: false },
      argo: procs.argo?.status() || { running: false }
    }
  };

  // minimal health logic: xray + argo wajib hidup
  if (!st.processes.xray.running || !st.processes.argo.running) st.ok = false;

  res.status(st.ok ? 200 : 503).json(st);
});

// subscription output
app.get('/sub', (req, res) => {
  const host = req.headers.host;

  // Direct (normal)
  const vlessDirect =
    `vless://${UUID}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=%2Fvless#VLESS_${host}`;
  const vmessDirectObj = {
    v: '2',
    ps: `VMESS_${host}`,
    add: host,
    port: '443',
    id: UUID,
    aid: '0',
    scy: 'auto',
    net: 'ws',
    type: 'none',
    host: host,
    path: '/vmess',
    tls: 'tls',
    sni: host
  };
  const vmessDirect = `vmess://${Buffer.from(JSON.stringify(vmessDirectObj)).toString('base64')}`;
  const trojanDirect =
    `trojan://${UUID}@${host}:443?security=tls&sni=${host}&type=ws&host=${host}&path=%2Ftrojan#TROJAN_${host}`;

  // CFIP-fronting (optional)
  const vlessFront =
    `vless://${UUID}@${CFIP}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=%2Fvless#VLESS_CFIP_${host}`;
  const vmessFrontObj = { ...vmessDirectObj, add: CFIP, sni: host };
  const vmessFront = `vmess://${Buffer.from(JSON.stringify(vmessFrontObj)).toString('base64')}`;
  const trojanFront =
    `trojan://${UUID}@${CFIP}:443?security=tls&sni=${host}&type=ws&host=${host}&path=%2Ftrojan#TROJAN_CFIP_${host}`;

  res.type('text/plain').send(
    [
      '# ===== DIRECT =====',
      vlessDirect,
      vmessDirect,
      trojanDirect,
      '',
      '# ===== CFIP FRONTING (optional) =====',
      `# CFIP=${CFIP}`,
      vlessFront,
      vmessFront,
      trojanFront,
      ''
    ].join('\n')
  );
});

app.listen(PORT, () => {
  console.log(`[SERVER] listening on :${PORT}`);
  startServices();
});
