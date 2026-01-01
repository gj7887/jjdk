'use strict';

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const { spawn } = require('child_process');
const express = require('express');
const axios = require('axios');
require('dotenv').config();

const TLS_PORTS = new Set(['443', '8443', '2096', '2087', '2083', '2053']);
const NODE_PROTOCOL_REGEX = /(vless|vmess|trojan|hysteria2|tuic):\/\//i;
const CLOUD_FLARE_HOST_REGEX = /https?:\/\/([a-z0-9.-]*trycloudflare.com)/i;
const SUBSCRIPTION_READY_MESSAGE = 'Subscription is not ready yet, please retry later.';

const env = loadEnv();
const paths = resolvePaths(env);
const subscriptionState = { encoded: null, plain: null, lastHostname: null };
const childProcesses = new Map();
const app = express();

main().catch((error) => {
  console.error('[FATAL] Unexpected error:', error);
  process.exit(1);
});

async function main() {
  console.log('[INIT] Starting nodejs-argo inspired deployer');
  await ensureDirectory(paths.baseDir);
  await deleteRemoteNodes(env, paths);
  await cleanupRuntime(paths);
  await writeXrayConfig(paths.configFile, env);

  const server = startHttpServer(env, subscriptionState);
  const xrayProcess = startXray(paths.configFile);
  registerProcess(xrayProcess, 'xray');

  const nezhaProcess = startNezhaAgent(env);
  if (nezhaProcess) {
    registerProcess(nezhaProcess, 'nezha-agent');
  }

  const cloudflared = startCloudflared(env, paths);
  registerProcess(cloudflared.process, 'cloudflared');

  try {
    const hostname = await cloudflared.hostnamePromise;
    console.log(`[TUNNEL] Online via ${hostname}`);

    const subscription = await buildSubscription(hostname, env);
    await writeSubscriptionFiles(subscription, paths);
    updateSubscriptionState(subscriptionState, subscription);
    await maybeUpload(env, subscription, paths);

    scheduleKeepAlive(env);
    scheduleCleanup(paths, env);
    setupShutdownHooks(server);
    console.log('[READY] Deployment finished successfully');
  } catch (error) {
    console.error('[FATAL] Unable to establish tunnel:', error);
    process.exit(1);
  }
}

function loadEnv() {
  const toString = (value, fallback = '') => {
    if (value === undefined || value === null) {
      return fallback;
    }
    return String(value).trim();
  };

  const toNumber = (value, fallback) => {
    if (value === undefined || value === null || value === '') {
      return fallback;
    }
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
  };

  const toBoolean = (value, fallback = false) => {
    if (value === undefined || value === null || value === '') {
      return fallback;
    }
    const normalized = String(value).trim().toLowerCase();
    return ['1', 'true', 'yes', 'on'].includes(normalized);
  };

  const sanitizeSubPath = (value) => {
    const trimmed = value.replace(/^\/+|\/+$|\s+/g, '');
    return trimmed || 'sub';
  };

  const projectUrlInput = toString(process.env.PROJECT_URL, '');
  const projectUrl = projectUrlInput.replace(/\/+$/, '');

  return {
    uploadUrl: toString(process.env.UPLOAD_URL, ''),        // 上传订阅地址
    projectUrl,
    projectUrlConfigured: Boolean(projectUrl),                // 是否启用项目上传 
    autoAccess: toBoolean(process.env.AUTO_ACCESS, false),             // 是否启用自动访问保持在线
    httpPort: toNumber(process.env.PORT ?? process.env.SERVER_PORT, 3000),          // http服务订阅端口
    argoPort: toNumber(process.env.ARGO_PORT, 8001),                    // xray监听端口，cloudflared隧道转发到该端口  
    uuid: toString(process.env.UUID, '89c13786-25aa-4520-b2e7-12cd60fb5202'),       // 在不同的平台运行需修改UUID
    nezhaServer: toString(process.env.NEZHA_SERVER, ''),          // 哪吒服务器地址
    nezhaPort: toString(process.env.NEZHA_PORT, ''),              // 哪吒服务器端口
    nezhaKey: toString(process.env.NEZHA_KEY, ''),                      // 哪吒服务器密钥
    nezhaTls: toBoolean(process.env.NEZHA_TLS, false),                  // 哪吒服务器是否使用TLS
    argoDomain: toString(process.env.ARGO_DOMAIN, ''),                    // 固定隧道域名,留空即启用临时隧道
    argoAuth: toString(process.env.ARGO_AUTH, ''),                        // 固定隧道密钥json或token,留空即启用临时隧道
    cfIp: toString(process.env.CFIP, 'www.visa.com.tw'),  // cloudflared 绑定的IP地址
    cfPort: toNumber(process.env.CFPORT, 443),  // cloudflared监听端口
    nodeNamePrefix: toString(process.env.NAME, ''), // 节点名称前缀
    filePath: toString(process.env.FILE_PATH, './tmp'), // 文件存储路径
    subPath: sanitizeSubPath(process.env.SUB_PATH || 'sub'),  // 订阅路径
    uploadTimeoutMs: toNumber(process.env.UPLOAD_TIMEOUT_MS, 8000), // 上传超时时间
    autoAccessIntervalMs: Math.max(60000, toNumber(process.env.AUTO_ACCESS_INTERVAL_MS, 10 * 60 * 1000)), // 自动访问间隔
    keepFilesSeconds: Math.max(0, toNumber(process.env.CLEANUP_SECONDS, 90)), // 保留临时文件时间
  };
}

function resolvePaths(envVars) {
  const baseDir = path.isAbsolute(envVars.filePath)
    ? envVars.filePath
    : path.join(process.cwd(), envVars.filePath);
  return {
    baseDir,
    configFile: path.join(baseDir, 'config.json'),
    tunnelCredentials: path.join(baseDir, 'tunnel.json'),
    tunnelConfig: path.join(baseDir, 'tunnel.yml'),
    subscriptionFile: path.join(baseDir, 'sub.txt'),
    nodeListFile: path.join(baseDir, 'list.txt'),
    logFile: path.join(baseDir, 'cloudflared.log'),
  };
}

async function ensureDirectory(dir) {
  await fsp.mkdir(dir, { recursive: true });
}

async function cleanupRuntime(currentPaths) {
  const targets = [
    currentPaths.configFile,
    currentPaths.tunnelCredentials,
    currentPaths.tunnelConfig,
    currentPaths.logFile,
    currentPaths.subscriptionFile,
    currentPaths.nodeListFile,
  ];
  await Promise.allSettled(targets.map((file) => fsp.rm(file, { force: true })));
}

function startHttpServer(envVars, state) {
  app.get('/', (req, res) => {
    res.json({
      status: 'ok',
      hostname: state.lastHostname,
      subscriptionReady: Boolean(state.encoded),
      subPath: `/${envVars.subPath}`,
    });
  });

  app.get(`/${envVars.subPath}`, (req, res) => {
    if (!state.encoded) {
      res.status(503).send(SUBSCRIPTION_READY_MESSAGE);
      return;
    }
    res.type('text/plain').send(state.encoded);
  });

  app.get('/healthz', (req, res) => {
    res.json({ ready: Boolean(state.encoded) });
  });

  return app.listen(envVars.httpPort, () => {
    console.log(`[HTTP] Listening on port ${envVars.httpPort}`);
  });
}

async function writeXrayConfig(configFile, envVars) {
  const config = {
    log: {
      access: '/dev/null',
      error: '/dev/null',
      loglevel: 'warning',
    },
    inbounds: [
      {
        port: envVars.argoPort,
        protocol: 'vless',
        settings: {
          clients: [{ id: envVars.uuid, flow: 'xtls-rprx-vision' }],
          decryption: 'none',
          fallbacks: [
            { dest: 3001 },
            { path: '/vless-argo', dest: 3002 },
            { path: '/vmess-argo', dest: 3003 },
            { path: '/trojan-argo', dest: 3004 },
          ],
        },
        streamSettings: { network: 'tcp' },
      },
      {
        port: 3001,
        listen: '127.0.0.1',
        protocol: 'vless',
        settings: {
          clients: [{ id: envVars.uuid }],
          decryption: 'none',
        },
        streamSettings: { network: 'tcp', security: 'none' },
      },
      {
        port: 3002,
        listen: '127.0.0.1',
        protocol: 'vless',
        settings: {
          clients: [{ id: envVars.uuid }],
          decryption: 'none',
        },
        streamSettings: {
          network: 'ws',
          security: 'none',
          wsSettings: { path: '/vless-argo' },
        },
        sniffing: {
          enabled: true,
          destOverride: ['http', 'tls', 'quic'],
          metadataOnly: false,
        },
      },
      {
        port: 3003,
        listen: '127.0.0.1',
        protocol: 'vmess',
        settings: {
          clients: [{ id: envVars.uuid, alterId: 0 }],
        },
        streamSettings: {
          network: 'ws',
          security: 'none',
          wsSettings: { path: '/vmess-argo' },
        },
        sniffing: {
          enabled: true,
          destOverride: ['http', 'tls', 'quic'],
          metadataOnly: false,
        },
      },
      {
        port: 3004,
        listen: '127.0.0.1',
        protocol: 'trojan',
        settings: {
          clients: [{ password: envVars.uuid }],
        },
        streamSettings: {
          network: 'ws',
          security: 'none',
          wsSettings: { path: '/trojan-argo' },
        },
        sniffing: {
          enabled: true,
          destOverride: ['http', 'tls', 'quic'],
          metadataOnly: false,
        },
      },
    ],
    dns: { servers: ['https+local://8.8.8.8/dns-query'] },
    outbounds: [
      { protocol: 'freedom', tag: 'direct' },
      { protocol: 'blackhole', tag: 'block' },
    ],
  };

  await fsp.writeFile(configFile, JSON.stringify(config, null, 2), 'utf8');
}

function startXray(configFile) {
  console.log('[XRAY] Launching core process');
  const child = spawn('xray', ['run', '-c', configFile], { stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.on('data', (data) => process.stdout.write(`[XRAY] ${data}`));
  child.stderr.on('data', (data) => process.stderr.write(`[XRAY] ${data}`));
  child.on('exit', (code) => {
    console.error(`[XRAY] exited with code ${code}`);
    process.exit(1);
  });
  child.on('error', (error) => {
    console.error('[XRAY] Failed to spawn:', error.message);
    process.exit(1);
  });
  return child;
}

function startNezhaAgent(envVars) {
  if (!envVars.nezhaServer || !envVars.nezhaKey) {
    console.log('[NEZHA] Variables not set, skipping');
    return null;
  }

  const endpoint = envVars.nezhaPort
    ? `${envVars.nezhaServer}:${envVars.nezhaPort}`
    : envVars.nezhaServer;

  const args = [
    '-s', endpoint,
    '-p', envVars.nezhaKey,
    '--disable-auto-update',
    '--report-delay', '4',
    '--skip-conn',
    '--skip-procs',
  ];

  const portToCheck = envVars.nezhaPort || endpoint.split(':')[1];
  if (envVars.nezhaTls || (portToCheck && TLS_PORTS.has(String(portToCheck)))) {
    args.push('--tls');
  }

  console.log('[NEZHA] Launching agent');
  try {
    const child = spawn('nezha-agent', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', (data) => process.stdout.write(`[NEZHA] ${data}`));
    child.stderr.on('data', (data) => process.stderr.write(`[NEZHA] ${data}`));
    child.on('exit', (code) => console.warn(`[NEZHA] exited with code ${code}`));
    child.on('error', (error) => console.error('[NEZHA] Spawn error:', error.message));
    return child;
  } catch (error) {
    console.error('[NEZHA] Failed to start nezha-agent:', error.message);
    return null;
  }
}

function startCloudflared(envVars, currentPaths) {
  console.log('[CLOUDFLARED] Initializing tunnel');
  const logStream = fs.createWriteStream(currentPaths.logFile, { flags: 'a' });
  const mode = determineTunnelMode(envVars);
  let args = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2'];

  if (mode.type === 'named') {
    if (!envVars.argoDomain) {
      throw new Error('ARGO_DOMAIN is required when using named tunnels');
    }
    fs.writeFileSync(currentPaths.tunnelCredentials, JSON.stringify(mode.payload));
    const yaml = [
      `tunnel: ${mode.payload.TunnelID}`,
      `credentials-file: ${currentPaths.tunnelCredentials}`,
      'protocol: http2',
      'ingress:',
      `  - hostname: ${envVars.argoDomain}`,
      `    service: http://127.0.0.1:${envVars.argoPort}`,
      '    originRequest:',
      '      noTLSVerify: true',
      '  - service: http_status:404',
      '',
    ].join('\n');
    fs.writeFileSync(currentPaths.tunnelConfig, yaml);
    args = ['tunnel', '--config', currentPaths.tunnelConfig, 'run'];
  } else if (mode.type === 'token') {
    if (!envVars.argoDomain) {
      throw new Error('ARGO_DOMAIN is required when using token based tunnels');
    }
    args = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2', 'run', '--token', mode.payload];
  } else {
    args = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2', '--url', `http://127.0.0.1:${envVars.argoPort}`];
  }

  const child = spawn('cloudflared', args, { stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.on('data', (data) => {
    logStream.write(`[STDOUT] ${data}`);
    process.stdout.write(`[CLOUDFLARED] ${data}`);
  });
  child.stderr.on('data', (data) => {
    logStream.write(`[STDERR] ${data}`);
    process.stderr.write(`[CLOUDFLARED] ${data}`);
  });
  child.on('close', () => logStream.end());

  const hostnamePromise = new Promise((resolve, reject) => {
    let resolved = false;
    const finish = (value) => {
      if (!resolved) {
        resolved = true;
        resolve(value);
      }
    };
    const fail = (error) => {
      if (!resolved) {
        resolved = true;
        reject(error);
      }
    };

    if (mode.type === 'named') {
      finish(envVars.argoDomain);
    } else if (mode.type === 'token') {
      finish(envVars.argoDomain);
    } else {
      const timeout = setTimeout(() => {
        fail(new Error('Timed out waiting for Cloudflare tunnel hostname'));
      }, 30000);

      const parse = (chunk) => {
        const text = chunk.toString();
        const match = text.match(CLOUD_FLARE_HOST_REGEX);
        if (match) {
          clearTimeout(timeout);
          finish(match[1]);
        }
      };

      child.stdout.on('data', parse);
      child.stderr.on('data', parse);
    }

    child.once('exit', (code) => fail(new Error(`cloudflared exited with code ${code}`)));
    child.once('error', fail);
  });

  return { process: child, hostnamePromise };
}

function determineTunnelMode(envVars) {
  const auth = envVars.argoAuth;
  if (!auth) {
    return { type: 'quick' };
  }

  try {
    const parsed = JSON.parse(auth);
    if (parsed && parsed.TunnelSecret && parsed.TunnelID) {
      return { type: 'named', payload: parsed };
    }
  } catch (_) {
    // ignore
  }

  if (/^[A-Za-z0-9=]{120,250}$/.test(auth)) {
    return { type: 'token', payload: auth };
  }

  return { type: 'quick' };
}

async function buildSubscription(hostname, envVars) {
  const ispTag = await fetchMetaTag();
  const displayName = envVars.nodeNamePrefix
    ? `${envVars.nodeNamePrefix}-${ispTag}`
    : ispTag;

  const vmess = {
    v: '2',
    ps: displayName,
    add: envVars.cfIp,
    port: String(envVars.cfPort),
    id: envVars.uuid,
    aid: '0',
    scy: 'none',
    net: 'ws',
    type: 'none',
    host: hostname,
    path: '/vmess-argo?ed=2560',
    tls: 'tls',
    sni: hostname,
    alpn: '',
    fp: 'firefox',
  };

  const nodes = [
    `vless://${envVars.uuid}@${envVars.cfIp}:${envVars.cfPort}?encryption=none&security=tls&sni=${hostname}&fp=firefox&type=ws&host=${hostname}&path=%2Fvless-argo%3Fed%3D2560#${displayName}`,
    `vmess://${Buffer.from(JSON.stringify(vmess)).toString('base64')}`,
    `trojan://${envVars.uuid}@${envVars.cfIp}:${envVars.cfPort}?security=tls&sni=${hostname}&fp=firefox&type=ws&host=${hostname}&path=%2Ftrojan-argo%3Fed%3D2560#${displayName}`,
  ];

  const encoded = Buffer.from(nodes.join('\n')).toString('base64');
  console.log('[SUB] Subscription generated');
  console.log(encoded);

  return { hostname, nodes, encoded };
}

async function fetchMetaTag() {
  const sources = [
    async () => {
      const { data } = await axios.get('https://ipapi.co/json/', { timeout: 3000 });
      if (data && data.country_code && data.org) {
        return `${data.country_code}_${sanitizeOrg(data.org)}`;
      }
      return null;
    },
    async () => {
      const { data } = await axios.get('http://ip-api.com/json/', { timeout: 3000 });
      if (data && data.status === 'success' && data.countryCode && data.org) {
        return `${data.countryCode}_${sanitizeOrg(data.org)}`;
      }
      return null;
    },
  ];

  for (const fn of sources) {
    try {
      const result = await fn();
      if (result) {
        return result;
      }
    } catch (error) {
      // ignore and continue
    }
  }

  return 'Unknown';
}

function sanitizeOrg(org) {
  return org.replace(/[^a-zA-Z0-9_-]/g, '');
}

async function writeSubscriptionFiles(subscription, currentPaths) {
  await fsp.writeFile(currentPaths.subscriptionFile, subscription.encoded, 'utf8');
  await fsp.writeFile(currentPaths.nodeListFile, subscription.nodes.join('\n'), 'utf8');
  console.log(`[SUB] Files saved to ${currentPaths.subscriptionFile}`);
}

function updateSubscriptionState(state, subscription) {
  state.encoded = subscription.encoded;
  state.plain = subscription.nodes.join('\n');
  state.lastHostname = subscription.hostname;
}

async function maybeUpload(envVars, subscription) {
  if (!envVars.uploadUrl) {
    return;
  }

  const headers = { 'Content-Type': 'application/json' };

  try {
    if (envVars.projectUrl && envVars.projectUrlConfigured) {
      const subscriptionUrl = `${envVars.projectUrl.replace(/\/+$/, '')}/${envVars.subPath}`;
      await axios.post(
        `${envVars.uploadUrl}/api/add-subscriptions`,
        { subscription: [subscriptionUrl] },
        { headers, timeout: envVars.uploadTimeoutMs }
      );
      console.log('[UPLOAD] Subscription URL uploaded successfully');
    } else {
      await axios.post(
        `${envVars.uploadUrl}/api/add-nodes`,
        { nodes: subscription.nodes },
        { headers, timeout: envVars.uploadTimeoutMs }
      );
      console.log('[UPLOAD] Nodes uploaded successfully');
    }
  } catch (error) {
    console.error('[UPLOAD] Failed to upload subscription:', error.message);
  }
}

async function deleteRemoteNodes(envVars, currentPaths) {
  if (!envVars.uploadUrl) {
    return;
  }
  try {
    const encoded = await fsp.readFile(currentPaths.subscriptionFile, 'utf8');
    const decoded = Buffer.from(encoded, 'base64').toString('utf8');
    const nodes = decoded.split(/\n+/).filter((line) => NODE_PROTOCOL_REGEX.test(line));
    if (!nodes.length) {
      return;
    }
    await axios.post(
      `${envVars.uploadUrl}/api/delete-nodes`,
      { nodes },
      { headers: { 'Content-Type': 'application/json' }, timeout: envVars.uploadTimeoutMs }
    );
    console.log('[UPLOAD] Removed historical nodes before deploying new ones');
  } catch (error) {
    if (error.code !== 'ENOENT') {
      console.warn('[UPLOAD] Skip deleting nodes:', error.message);
    }
  }
}

function scheduleKeepAlive(envVars) {
  if (!envVars.autoAccess || !envVars.projectUrl || !envVars.projectUrlConfigured) {
    console.log('[KEEPALIVE] Disabled');
    return;
  }

  const trigger = async () => {
    try {
      await axios.post(
        'https://oooo.serv00.net/add-url',
        { url: envVars.projectUrl },
        { headers: { 'Content-Type': 'application/json' }, timeout: 5000 }
      );
      console.log('[KEEPALIVE] Project URL pinged successfully');
    } catch (error) {
      console.warn('[KEEPALIVE] Failed to ping project URL:', error.message);
    }
  };

  trigger();
  setInterval(trigger, envVars.autoAccessIntervalMs).unref();
}

function scheduleCleanup(currentPaths, envVars) {
  if (!envVars.keepFilesSeconds) {
    return;
  }
  setTimeout(() => {
    const targets = [
      currentPaths.configFile,
      currentPaths.tunnelCredentials,
      currentPaths.tunnelConfig,
      currentPaths.logFile,
    ];
    targets.forEach((file) => {
      fsp.rm(file, { force: true }).catch(() => {});
    });
    console.log('[CLEANUP] Temporary files removed');
  }, envVars.keepFilesSeconds * 1000).unref();
}

function registerProcess(proc, label) {
  if (!proc) {
    return;
  }
  childProcesses.set(label, proc);
}

function setupShutdownHooks(server) {
  const shutdown = () => {
    console.log('[SHUTDOWN] Stopping processes');
    server.close(() => console.log('[HTTP] Server closed'));
    for (const [label, proc] of childProcesses.entries()) {
      if (proc && !proc.killed) {
        proc.kill('SIGTERM');
        console.log(`[SHUTDOWN] Sent SIGTERM to ${label}`);
      }
    }
    setTimeout(() => process.exit(0), 2000);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
  process.on('unhandledRejection', (error) => {
    console.error('[UNHANDLED] Rejection:', error);
  });
}
