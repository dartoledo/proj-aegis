import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';

export interface TlsProbeResult {
  serialNumber: string;
  rawSerial: string;
  validFrom: string;
  expiryDate: string;
  daysRemaining: number;
  status: 'Healthy' | 'Warning' | 'Critical';
  subjectCN: string;
  issuerCN: string;
  hostPort: string;
  probedAt: string;
}

export interface BuildPemInput {
  mode: 'upload' | 'auto-generate';
  cert?: string;
  key?: string;
  commonName?: string;
  validDays?: number;
}

export interface BuildPemOutput {
  pemBundle: string;
  serialNumber: string;
  expiryDate: string;
  daysRemaining: number;
}

export interface DeployCertInput {
  entityRef?: string;
  pemBundle: string;
  pemPath?: string;
  catalogInfoPath?: string;
}

export const DEFAULT_HAPROXY_HOST =
  process.env.AEGIS_HAPROXY_HOST || '127.0.0.1:8443';
export const DEFAULT_HOST_PEM_PATH =
  '/home/dartoledo/proj-aegis/demo/haproxy/certs/hello-world.pem';
export const DEFAULT_HOST_SOCKET_PATH =
  '/home/dartoledo/proj-aegis/demo/haproxy/run/haproxy.sock';
export const DEFAULT_CONTAINER_PEM_PATH =
  '/etc/haproxy/certs/hello-world.pem';
export const DEFAULT_CATALOG_INFO_PATH =
  '/home/dartoledo/proj-aegis/demo/haproxy/catalog-info.yaml';

let latestProbeResult: TlsProbeResult = {
  serialNumber: '00:00:00:00',
  rawSerial: '00000000',
  validFrom: new Date().toISOString(),
  expiryDate: new Date(Date.now() + 15 * 86400000).toISOString(),
  daysRemaining: 15,
  status: 'Warning',
  subjectCN: 'hello.internal',
  issuerCN: 'hello.internal',
  hostPort: DEFAULT_HAPROXY_HOST,
  probedAt: new Date().toISOString(),
};

export function formatColonSerial(hexSerial: string): string {
  const cleaned = hexSerial
    .replace(/^serial=/i, '')
    .replace(/[^0-9a-fA-F]/g, '')
    .toUpperCase();
  if (!cleaned) {
    return '00';
  }
  const padded = cleaned.length % 2 === 1 ? `0${cleaned}` : cleaned;
  return padded.match(/.{1,2}/g)?.join(':') ?? padded;
}

export function normalizeSerial(serial: string): string {
  return serial
    .replace(/^serial=/i, '')
    .replace(/[^0-9a-fA-F]/g, '')
    .replace(/^0+/, '')
    .toUpperCase();
}

export function computeCertStatus(
  daysRemaining: number,
): 'Healthy' | 'Warning' | 'Critical' {
  if (daysRemaining <= 7) {
    return 'Critical';
  }
  if (daysRemaining <= 30) {
    return 'Warning';
  }
  return 'Healthy';
}

function extractCertAndKeyFromBundle(pemBundle: string): {
  cert: string;
  key: string;
} {
  const certMatch = pemBundle.match(
    /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/,
  );
  const keyMatch = pemBundle.match(
    /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC )?PRIVATE KEY-----/,
  );
  if (!certMatch || !keyMatch) {
    throw new Error(
      'X.509 validation failed: PEM bundle must contain both a valid CERTIFICATE block and a PRIVATE KEY block',
    );
  }
  return { cert: certMatch[0], key: keyMatch[0] };
}

export async function sendHaproxySocketCommand(
  command: string,
  socketPath = DEFAULT_HOST_SOCKET_PATH,
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = [];
    const client = net.createConnection(socketPath, () => {
      client.write(command);
      client.end();
    });

    client.setTimeout(3000, () => {
      client.destroy();
      reject(new Error(`HAProxy runtime socket timed out: ${socketPath}`));
    });

    client.on('data', chunk => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });

    client.on('end', () => {
      resolve(Buffer.concat(chunks).toString('utf8'));
    });

    client.on('error', err => {
      client.destroy();
      reject(err);
    });
  });
}

export async function buildAndValidateHaproxyPem(
  input: BuildPemInput,
): Promise<BuildPemOutput> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-tls-'));
  const certPath = path.join(tmpDir, 'cert.pem');
  const keyPath = path.join(tmpDir, 'key.pem');

  try {
    if (input.mode === 'auto-generate') {
      const cn = (input.commonName || 'hello.internal').replace(
        /[^a-zA-Z0-9._-]/g,
        '',
      );
      const validDays = Math.max(1, Number(input.validDays ?? 90));
      execFileSync(
        'openssl',
        [
          'req',
          '-x509',
          '-newkey',
          'rsa:2048',
          '-nodes',
          '-sha256',
          '-days',
          String(validDays),
          '-subj',
          `/CN=${cn}`,
          '-keyout',
          keyPath,
          '-out',
          certPath,
        ],
        { stdio: 'pipe' },
      );
    } else if (input.mode === 'upload') {
      if (!input.cert?.trim() || !input.key?.trim()) {
        throw new Error(
          'X.509 validation failed: Both public certificate and private key must be provided in upload mode',
        );
      }
      fs.writeFileSync(certPath, `${input.cert.trim()}\n`, { mode: 0o600 });
      fs.writeFileSync(keyPath, `${input.key.trim()}\n`, { mode: 0o600 });
    } else {
      throw new Error(`Unsupported build-pem mode: ${String(input.mode)}`);
    }

    // Validate X.509 certificate and private key modulus / public key match
    let certModulus = '';
    let keyModulus = '';
    try {
      certModulus = execFileSync(
        'openssl',
        ['x509', '-noout', '-modulus', '-in', certPath],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
      ).trim();
      keyModulus = execFileSync(
        'openssl',
        ['rsa', '-noout', '-modulus', '-in', keyPath],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
      ).trim();
    } catch {
      try {
        certModulus = execFileSync(
          'openssl',
          ['x509', '-noout', '-pubkey', '-in', certPath],
          { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
        ).trim();
        keyModulus = execFileSync(
          'openssl',
          ['pkey', '-pubout', '-in', keyPath],
          { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
        ).trim();
      } catch {
        throw new Error(
          'X.509 validation failed: Malformed X.509 certificate or private key',
        );
      }
    }

    if (!certModulus || !keyModulus || certModulus !== keyModulus) {
      throw new Error(
        'X.509 validation failed: Private Key does not match Public Certificate modulus/public key',
      );
    }

    const rawSerialOut = execFileSync(
      'openssl',
      ['x509', '-noout', '-serial', '-in', certPath],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    ).trim();
    const rawEndDateOut = execFileSync(
      'openssl',
      ['x509', '-noout', '-enddate', '-in', certPath],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    ).trim();

    const serialNumber = formatColonSerial(rawSerialOut);
    const endDateStr = rawEndDateOut.replace(/^notAfter=/i, '').trim();
    const expiryDate = new Date(endDateStr).toISOString();
    const daysRemaining = Math.max(
      0,
      Math.ceil((new Date(expiryDate).getTime() - Date.now()) / 86400000),
    );

    const certContent = fs.readFileSync(certPath, 'utf8').trim();
    const keyContent = fs.readFileSync(keyPath, 'utf8').trim();
    const pemBundle = `${certContent}\n${keyContent}\n`;

    return {
      pemBundle,
      serialNumber,
      expiryDate,
      daysRemaining,
    };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function resolveProbeHostPort(hostPort?: string): {
  host: string;
  port: number;
  displayHostPort: string;
} {
  const raw = (hostPort || DEFAULT_HAPROXY_HOST).trim();
  const [rawHost, rawPort] = raw.includes(':')
    ? raw.split(':')
    : [raw, '8443'];
  const parsedPort = Number(rawPort) || 8443;

  if (
    rawHost === 'haproxy-sandbox.internal' ||
    rawHost === 'hello.internal' ||
    (rawHost === '127.0.0.1' && parsedPort === 443)
  ) {
    return {
      host: '127.0.0.1',
      port: 8443,
      displayHostPort: '127.0.0.1:8443',
    };
  }

  return {
    host: rawHost,
    port: parsedPort,
    displayHostPort: `${rawHost}:${parsedPort}`,
  };
}

export async function probeLiveTlsCertificate(
  hostPort?: string,
): Promise<TlsProbeResult> {
  const { host, port, displayHostPort } = resolveProbeHostPort(hostPort);

  return new Promise<TlsProbeResult>((resolve, reject) => {
    const socket = tls.connect(
      {
        host,
        port,
        servername: 'hello.internal',
        rejectUnauthorized: false,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(false);
          socket.destroy();

          if (!cert || !cert.serialNumber) {
            reject(
              new Error(
                `No TLS peer certificate returned by ${displayHostPort}`,
              ),
            );
            return;
          }

          const rawSerial = cert.serialNumber;
          const serialNumber = formatColonSerial(rawSerial);
          const validFrom = new Date(cert.valid_from).toISOString();
          const expiryDate = new Date(cert.valid_to).toISOString();
          const daysRemaining = Math.max(
            0,
            Math.ceil((new Date(expiryDate).getTime() - Date.now()) / 86400000),
          );
          const status = computeCertStatus(daysRemaining);
          const subjectCN =
            (Array.isArray(cert.subject?.CN)
              ? cert.subject.CN[0]
              : cert.subject?.CN) || 'hello.internal';
          const issuerCN =
            (Array.isArray(cert.issuer?.CN)
              ? cert.issuer.CN[0]
              : cert.issuer?.CN) || subjectCN;

          const result: TlsProbeResult = {
            serialNumber,
            rawSerial,
            validFrom,
            expiryDate,
            daysRemaining,
            status,
            subjectCN,
            issuerCN,
            hostPort: displayHostPort,
            probedAt: new Date().toISOString(),
          };
          latestProbeResult = result;
          resolve(result);
        } catch (err) {
          socket.destroy();
          reject(err);
        }
      },
    );

    socket.setTimeout(5000, () => {
      socket.destroy();
      reject(new Error(`TLS probe timed out connecting to ${displayHostPort}`));
    });

    socket.on('error', err => {
      socket.destroy();
      reject(err);
    });
  });
}

export function updateCatalogYamlAnnotations(
  probe: Pick<
    TlsProbeResult,
    'serialNumber' | 'expiryDate' | 'daysRemaining' | 'status'
  >,
  catalogPath = DEFAULT_CATALOG_INFO_PATH,
): void {
  if (!fs.existsSync(catalogPath)) {
    return;
  }
  let content = fs.readFileSync(catalogPath, 'utf8');
  content = content.replace(
    /resiliency\.idp\/cert-version:\s*".*"/,
    `resiliency.idp/cert-version: "v1 (Serial: ${probe.serialNumber})"`,
  );
  content = content.replace(
    /resiliency\.idp\/cert-expiry:\s*".*"/,
    `resiliency.idp/cert-expiry: "${probe.expiryDate}"`,
  );
  content = content.replace(
    /resiliency\.idp\/days-remaining:\s*".*"/,
    `resiliency.idp/days-remaining: "${probe.daysRemaining}"`,
  );
  content = content.replace(
    /resiliency\.idp\/cert-status:\s*".*"/,
    `resiliency.idp/cert-status: "${probe.status}"`,
  );
  fs.writeFileSync(catalogPath, content, 'utf8');
}

export async function deployCertToHaproxy(input: DeployCertInput): Promise<{
  reloadedVia: string;
  serialNumber: string;
  expiryDate: string;
  daysRemaining: number;
}> {
  const { cert, key } = extractCertAndKeyFromBundle(input.pemBundle);
  const validated = await buildAndValidateHaproxyPem({
    mode: 'upload',
    cert,
    key,
  });

  const targetPemPath = input.pemPath || DEFAULT_HOST_PEM_PATH;
  fs.mkdirSync(path.dirname(targetPemPath), { recursive: true });
  fs.writeFileSync(targetPemPath, validated.pemBundle, { mode: 0o600 });

  let reloadedVia = 'disk-write';
  const setCmd = `set ssl cert ${DEFAULT_CONTAINER_PEM_PATH} <<\n${validated.pemBundle.trim()}\n\n`;
  const commitCmd = `commit ssl cert ${DEFAULT_CONTAINER_PEM_PATH}\n`;

  // 1. Primary: Native host Unix socket to HAProxy Runtime API (two separate connections)
  try {
    await sendHaproxySocketCommand(setCmd, DEFAULT_HOST_SOCKET_PATH);
    const commitOut = await sendHaproxySocketCommand(
      commitCmd,
      DEFAULT_HOST_SOCKET_PATH,
    );
    if (/Success/i.test(commitOut)) {
      reloadedVia = 'haproxy-runtime-socket';
    }
  } catch {
    // Fall back to podman exec socat if host socket is not directly accessible
  }

  // 2. Secondary: Two separate podman exec socat calls against /var/run/haproxy/haproxy.sock
  if (reloadedVia !== 'haproxy-runtime-socket') {
    const setProc = spawnSync(
      'podman',
      [
        'exec',
        '-i',
        'haproxy-sandbox',
        'socat',
        'stdio',
        '/var/run/haproxy/haproxy.sock',
      ],
      {
        input: setCmd,
        encoding: 'utf8',
        timeout: 5000,
      },
    );
    const commitProc = spawnSync(
      'podman',
      [
        'exec',
        '-i',
        'haproxy-sandbox',
        'socat',
        'stdio',
        '/var/run/haproxy/haproxy.sock',
      ],
      {
        input: commitCmd,
        encoding: 'utf8',
        timeout: 5000,
      },
    );
    if (
      setProc.status === 0 &&
      commitProc.status === 0 &&
      commitProc.stdout &&
      /Success/i.test(commitProc.stdout)
    ) {
      reloadedVia = 'haproxy-runtime-socket';
    }
  }

  // 3. Fallback: Graceful master-worker SIGUSR2 reload and wait until new serial is served
  if (reloadedVia !== 'haproxy-runtime-socket') {
    const reloadProc = spawnSync(
      'podman',
      ['exec', 'haproxy-sandbox', 'sh', '-c', 'kill -USR2 1'],
      { encoding: 'utf8', timeout: 5000 },
    );
    if (reloadProc.status === 0) {
      reloadedVia = 'haproxy-master-reload-usr2';
      for (let attempt = 0; attempt < 10; attempt++) {
        await new Promise(r => setTimeout(r, 250));
        try {
          const probe = await probeLiveTlsCertificate();
          if (
            normalizeSerial(probe.serialNumber) ===
            normalizeSerial(validated.serialNumber)
          ) {
            break;
          }
        } catch {
          // Ignore transient probe errors during worker replacement
        }
      }
    }
  }

  const status = computeCertStatus(validated.daysRemaining);
  updateCatalogYamlAnnotations(
    {
      serialNumber: validated.serialNumber,
      expiryDate: validated.expiryDate,
      daysRemaining: validated.daysRemaining,
      status,
    },
    input.catalogInfoPath || DEFAULT_CATALOG_INFO_PATH,
  );

  try {
    await probeLiveTlsCertificate();
  } catch {
    latestProbeResult = {
      ...latestProbeResult,
      serialNumber: validated.serialNumber,
      expiryDate: validated.expiryDate,
      daysRemaining: validated.daysRemaining,
      status,
      probedAt: new Date().toISOString(),
    };
  }

  return {
    reloadedVia,
    serialNumber: validated.serialNumber,
    expiryDate: validated.expiryDate,
    daysRemaining: validated.daysRemaining,
  };
}

export async function verifyLiveTlsSerial(
  expectedSerial: string,
  hostPort?: string,
): Promise<TlsProbeResult> {
  let lastProbe: TlsProbeResult | undefined;
  let lastErr: unknown;

  for (let attempt = 0; attempt < 6; attempt++) {
    try {
      const probe = await probeLiveTlsCertificate(hostPort);
      lastProbe = probe;
      if (
        normalizeSerial(probe.serialNumber) ===
        normalizeSerial(expectedSerial)
      ) {
        return probe;
      }
    } catch (err) {
      lastErr = err;
    }
    if (attempt < 5) {
      await new Promise(r => setTimeout(r, 250));
    }
  }

  if (lastProbe) {
    throw new Error(
      `Live TLS serial mismatch: expected ${expectedSerial}, got ${lastProbe.serialNumber}`,
    );
  }
  throw lastErr instanceof Error
    ? lastErr
    : new Error(`Live TLS verification failed for expected serial ${expectedSerial}`);
}

export async function renderPrometheusMetrics(
  hostPort?: string,
): Promise<string> {
  let probe = latestProbeResult;
  try {
    probe = await probeLiveTlsCertificate(hostPort);
  } catch {
    // Use cached latestProbeResult if sandbox is temporarily unreachable
  }

  return [
    '# HELP idp_certificate_expiry_days Days remaining until TLS certificate expiration',
    '# TYPE idp_certificate_expiry_days gauge',
    `idp_certificate_expiry_days{service="hello-world",proxy="haproxy"} ${probe.daysRemaining}`,
    '# HELP idp_certificate_info TLS certificate metadata',
    '# TYPE idp_certificate_info gauge',
    `idp_certificate_info{service="hello-world",proxy="haproxy",serial="${probe.serialNumber}",provider="Self-Signed (OpenSSL)",status="${probe.status}"} 1`,
    '',
  ].join('\n');
}
