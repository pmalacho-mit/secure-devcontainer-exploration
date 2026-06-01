import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import devcontainer from "../.suede/programmatic-docker-suede/devcontainer.js";

const MAX_BODY_BYTES = 50 * 1024 * 1024; // 50 MB

const setCors = (response: ServerResponse) => {
  response.setHeader("Access-Control-Allow-Origin", "*");
  response.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type");
};

const readBody = (request: IncomingMessage) =>
  new Promise((resolve, reject) => {
    let body = "";
    request.on("data", (chunk: Buffer) =>
      body.length + chunk.length > MAX_BODY_BYTES
        ? request.destroy(new Error("Request body exceeded 50 MB limit"))
        : (body += chunk.toString()),
    );
    request.on("end", () => {
      try {
        resolve(JSON.parse(body));
      } catch (e) {
        reject(e);
      }
    });
    request.on("error", reject);
  });

type OnMessage = (payload: {
  route: string;
  body: Awaited<ReturnType<typeof readBody>>;
  close: () => void;
}) => void;

/**
 * Creates an HTTP server that:
 *   - handles CORS and OPTIONS preflight,
 *   - reads and parses each POST body as JSON,
 *   - extracts the URL path as a `route` string (e.g. `""`, `"discover"`, `"chromium"`),
 *   - calls `onMessage({ route, body, close })` for every successful POST.
 *
 * Requests with malformed JSON bodies are silently dropped. `close()` is passed into
 * each `onMessage` call so handlers can self-close when done; it also backs the `close`
 * returned in the resolved value. `onTimeout` is called when the deadline fires — callers
 * use it to reject any pending promises they are managing.
 *
 * The server binds to `0.0.0.0` on an OS-assigned port and returns a URL built from
 * the devcontainer's non-loopback IP so it is reachable from browser containers sharing
 * the devcontainer network.
 */
export const createHttpListener = ({
  onMessage,
  timeout,
  onTimeout,
}: {
  onMessage: OnMessage;
  timeout: number;
  onTimeout: () => void;
}) =>
  new Promise<{ url: string; close: () => void }>((resolve) => {
    const server = createServer(async (request, response) => {
      setCors(response);
      if (request.method === "OPTIONS") {
        response.writeHead(204);
        response.end();
        return;
      }
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end("{}");
      try {
        const route = (request.url ?? "/").replace(/^\/+/, "").split("?")[0];
        const body = await readBody(request);
        onMessage({ route, close, body });
      } catch {
        // malformed body — ignore
      }
    });

    const timer = setTimeout(() => {
      server.close();
      onTimeout();
    }, timeout);

    const close = () => {
      clearTimeout(timer);
      server.close();
    };

    server.listen(0, "0.0.0.0", () => {
      const { port } = server.address() as { port: number };
      resolve({ url: `http://${devcontainer.ip()}:${port}`, close });
    });
  });
