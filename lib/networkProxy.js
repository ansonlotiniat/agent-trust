import http from "node:http";
import net from "node:net";
import { URL } from "node:url";
import pc from "./colors.js";
import { evaluatePolicy } from "./policy.js";

export async function startNetworkProxy(config, audit, assume) {
  if (!config.network.proxyEnv) return undefined;

  const server = http.createServer();
  const sockets = new Set();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  server.on("request", (req, res) => {
    void handleHttpRequest(config, audit, assume, req, res);
  });
  server.on("connect", (req, clientSocket, head) => {
    void handleConnect(config, audit, assume, req, clientSocket, head);
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") return undefined;

  return {
    url: `http://127.0.0.1:${address.port}`,
    close: () => new Promise((resolve, reject) => {
      for (const socket of sockets) socket.destroy();
      server.close((error) => error ? reject(error) : resolve());
    })
  };
}

async function handleConnect(config, audit, assume, req, clientSocket, head) {
  const target = req.url ?? "";
  const [host, portText] = target.split(":");
  const port = Number(portText || 443);
  const decision = await decideNetwork(config, audit, assume, host, port, "CONNECT");
  if (decision !== "allow") {
    clientSocket.write("HTTP/1.1 403 Forbidden\r\n\r\nAgent Trust denied network target\n");
    clientSocket.destroy();
    return;
  }

  const serverSocket = net.connect(port, host, () => {
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head.length) serverSocket.write(head);
    serverSocket.pipe(clientSocket);
    clientSocket.pipe(serverSocket);
  });
  serverSocket.on("error", () => clientSocket.destroy());
}

async function handleHttpRequest(config, audit, assume, req, res) {
  let target;
  try {
    target = new URL(req.url ?? "");
  } catch {
    res.writeHead(400);
    res.end("Agent Trust expected an absolute proxy URL\n");
    return;
  }

  const decision = await decideNetwork(config, audit, assume, target.hostname, Number(target.port || 80), req.method ?? "GET");
  if (decision !== "allow") {
    res.writeHead(403);
    res.end("Agent Trust denied network target\n");
    return;
  }

  const upstream = http.request({
    host: target.hostname,
    port: Number(target.port || 80),
    method: req.method,
    path: `${target.pathname}${target.search}`,
    headers: req.headers
  }, (upstreamRes) => {
    res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers);
    upstreamRes.pipe(res);
  });
  upstream.on("error", (error) => {
    res.writeHead(502);
    res.end(`Agent Trust proxy error: ${error.message}\n`);
  });
  req.pipe(upstream);
}

async function decideNetwork(config, audit, assume, host, port, method) {
  const cleanHost = (host ?? "").toLowerCase();
  const policy = evaluatePolicy(config, {
    kind: "network",
    networkHost: cleanHost
  });
  const decision = policy.decision === "ask" ? (assume ?? "deny") : policy.decision;
  await audit.append({
    type: "network.preflight",
    decision,
    ruleId: policy.ruleId,
    reason: policy.reason,
    subject: {
      host: cleanHost,
      port,
      method
    }
  });

  if (decision === "deny") {
    console.error(`${pc.red("denied network")} ${method} ${cleanHost}:${port} ${policy.reason}`);
  }

  return decision;
}
