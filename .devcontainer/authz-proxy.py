#!/usr/bin/env python3
# authz-proxy.py
# Body-inspecting Docker gate. Sits in FRONT of tecnativa/docker-socket-proxy:
#
#   app  (DOCKER_HOST=tcp://docker-authz:2375)
#     -> this shim            (polices POST /containers/create and /exec by content)
#       -> docker-endpoint-proxy  (tecnativa: coarse endpoint ACL, holds the real socket)
#         -> /var/run/docker.sock
#
# Policy: a container created through this shim may not have MORE access than the
# dev container -- no privileged, no added capabilities, no devices, no host or
# cross-container namespaces, no host bind mounts outside the workspace, and it may
# not attach to the proxy ("gate") network. Every container the shim creates is
# stamped with a label; `docker exec`, `attach`, and `docker cp` (the
# /containers/{id}/archive read+write endpoint) are permitted ONLY into containers
# carrying that label. Anything it cannot parse is denied (fail closed).
#
# Bind mounts have THREE disguises, all closed here:
#   1. HostConfig.Binds / Mounts(type=bind)          -> source must be in workspace
#   2. a `local`-driver VOLUME bound to a host path   -> /volumes/create is inspected
#      (type=none,o=bind,device=/), mounted by name      (check_volume_create), and a
#      or inline (Mounts[].VolumeOptions.DriverConfig)    named-volume backstop resolves
#                                                          by-reference mounts via the daemon
#   3. VolumesFrom (could inherit the proxy socket)   -> denied outright
# Volume creation is NOT body-inspected by tecnativa (VOLUMES=1 passes it straight
# through), so without (2) a "named volume" was a host bind the Binds/Mounts checks
# never saw -- a full host-root escape. That hole is now closed.
#
# Networks are per-devcontainer (Compose scopes them to the project), so the gate
# network's name is dynamic. The shim recognises it three ways: by Compose suffix
# (".._gate"), by discovering the gate network's real name AND id at runtime (it
# resolves the proxy's address and finds which network it sits on), and -- as a
# definitive backstop on the create/connect paths -- by asking the daemon whether
# the network a request would join actually hosts the proxy (network_is_gate). The
# last one resolves raw/short network ids the way Docker itself does, so joining the
# gate by a 12-char id (a prefix of the full id, not an exact cache match) can't slip
# past either a name-only or a full-id-only check.
import json, os, re, socket, select, threading, time

UP_HOST = os.environ.get("UPSTREAM_HOST", "docker-endpoint-proxy")
UP_PORT = int(os.environ.get("UPSTREAM_PORT", "2375"))
LISTEN  = ("0.0.0.0", 2375)
ALLOWED = [p for p in os.environ.get("ALLOWED_BIND_PREFIXES", "").split(":") if p]
OWN_LABEL = "authz.owned"
GATE_RE = re.compile(os.environ.get("GATE_NET_PATTERN", r"(^|[-_])gate$"))

CREATE_RE  = re.compile(r"^/(v[\d.]+/)?containers/create(\?|$)")
EXEC_RE    = re.compile(r"^/(v[\d.]+/)?containers/([^/]+)/exec(\?|$)")
ATTACH_RE  = re.compile(r"^/(v[\d.]+/)?containers/([^/]+)/attach(/ws)?(\?|$)")
CONNECT_RE = re.compile(r"^/(v[\d.]+/)?networks/([^/]+)/connect(\?|$)")
# `docker cp` (read OR write a container's filesystem) -- same cross-container risk
# class as exec/attach, so gate it by ownership too.
ARCHIVE_RE = re.compile(r"^/(v[\d.]+/)?containers/([^/]+)/archive(\?|$)")
# `docker volume create` -- NOT body-inspected by tecnativa (VOLUMES=1 passes it),
# yet the built-in `local` driver can bind a host path (type=none,o=bind,device=/),
# turning a "named volume" into a host bind that the Binds/Mounts checks never see.
VOLCREATE_RE = re.compile(r"^/(v[\d.]+/)?volumes/create(\?|$)")


# ---- upstream helpers -------------------------------------------------------
def upstream():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((UP_HOST, UP_PORT))
    return s


def _extract_json(body):
    starts = [i for i in (body.find(b"{"), body.find(b"[")) if i != -1]
    ends   = [i for i in (body.rfind(b"}"), body.rfind(b"]")) if i != -1]
    if not starts or not ends:
        raise ValueError("no json in response")
    return json.loads(body[min(starts):max(ends) + 1])


def http_get_json(path):
    u = upstream()
    try:
        u.sendall(("GET %s HTTP/1.1\r\nHost: d\r\nConnection: close\r\n\r\n" % path).encode())
        resp = b""
        while True:
            c = u.recv(65536)
            if not c:
                break
            resp += c
    finally:
        u.close()
    return _extract_json(resp.split(b"\r\n\r\n", 1)[1])


# ---- gate-network discovery (cached) ---------------------------------------
_gate_cache = set()
_gate_lock = threading.Lock()


def discover_gate():
    """Return {name, id} of the network the upstream proxy lives on, or empty."""
    try:
        proxy_ip = socket.gethostbyname(UP_HOST)
    except Exception:
        return set()
    out = set()
    try:
        nets = http_get_json("/networks")
    except Exception:
        return out
    for n in nets:
        nid = n.get("Id")
        if not nid:
            continue
        try:
            detail = http_get_json("/networks/%s" % nid)
        except Exception:
            continue
        for c in (detail.get("Containers") or {}).values():
            if (c.get("IPv4Address") or "").split("/")[0] == proxy_ip:
                if n.get("Name"):
                    out.add(n["Name"])
                out.add(nid)
                return out
    return out


def gate_ids():
    global _gate_cache
    if _gate_cache:
        return _gate_cache
    with _gate_lock:
        if not _gate_cache:
            found = discover_gate()
            if found:
                _gate_cache = found
                print("discovered gate network:", found, flush=True)
            return found
        return _gate_cache


def is_gate_net(name):
    if not name:
        return False
    if GATE_RE.search(name):     # Compose suffix, e.g. <project>_gate (any project)
        return True
    if name in gate_ids():       # discovered name OR id (defeats join-by-id)
        return True
    return False


def network_is_gate(net):
    """True if network `net` currently hosts the upstream proxy. Backstop for the
    `network connect` path: catches the gate by membership even if the suffix
    pattern and the discovery cache both miss (e.g. join-by-raw-id pre-discovery)."""
    try:
        proxy_ip = socket.gethostbyname(UP_HOST)
        detail = http_get_json("/networks/%s" % net)
    except Exception:
        return False
    for c in (detail.get("Containers") or {}).values():
        if (c.get("IPv4Address") or "").split("/")[0] == proxy_ip:
            return True
    return False


# ---- create policy ----------------------------------------------------------
def bind_ok(src):
    return any(src == p or src.startswith(p.rstrip("/") + "/") for p in ALLOWED)


def check_create(body):                        # None = allow, str = deny reason
    try:
        cfg = json.loads(body)
    except Exception:
        return "unparseable create body"
    hc = cfg.get("HostConfig") or {}
    if hc.get("Privileged"):       return "privileged"
    if hc.get("CapAdd"):           return "adds capabilities"
    if hc.get("Devices") or hc.get("DeviceRequests") or hc.get("DeviceCgroupRules"):
        return "device passthrough"
    if hc.get("VolumesFrom"):      return "VolumesFrom (could inherit the proxy socket)"
    for k in ("PidMode", "IpcMode", "UTSMode", "UsernsMode"):
        if hc.get(k):              return "shares namespace: " + k
    nm = hc.get("NetworkMode") or ""
    if nm == "host" or nm.startswith("container:"):    return "NetworkMode " + nm
    if is_gate_net(nm):                                return "joins the gate network: " + nm
    for net in (cfg.get("NetworkingConfig") or {}).get("EndpointsConfig") or {}:
        if is_gate_net(net):                           return "attaches to the gate network: " + net
    for opt in hc.get("SecurityOpt") or []:
        if "unconfined" in opt or "no-new-privileges:false" in opt.replace(" ", ""):
            return "weakens confinement: " + opt
    for b in hc.get("Binds") or []:
        if not bind_ok(b.split(":")[0]):   return "bind outside workspace: " + b
    for m in hc.get("Mounts") or []:
        mtype = m.get("Type")
        if mtype == "bind" and not bind_ok(m.get("Source", "")):
            return "bind outside workspace: " + m.get("Source", "")
        if mtype == "volume":
            # A `volume` mount can inline a host-bind local volume right in the
            # create body (VolumeOptions.DriverConfig.Options.device), bypassing the
            # `bind` checks above without ever touching /volumes/create.
            reason = vol_inline_bind(m)
            if reason:                     return reason
    return None


def vol_device_ok(dev):
    """A local-volume `device` opt is OK only if it resolves under the workspace
    allowlist. Strips an nfs-style leading ':' so `:/export` is judged on `/export`
    (and thus denied unless allow-listed -- fail closed, the stated principle)."""
    if not dev:
        return True
    src = dev[1:] if dev.startswith(":") else dev
    return bind_ok(src)


def vol_inline_bind(m):                         # None = ok, str = deny reason
    opts = (((m.get("VolumeOptions") or {}).get("DriverConfig") or {}).get("Options")) or {}
    if not vol_device_ok(opts.get("device")):
        return "volume mount binds host path outside workspace: " + opts.get("device", "")
    return None


def check_volume_create(body):                  # None = allow, str = deny reason
    try:
        cfg = json.loads(body)
    except Exception:
        return "unparseable volume-create body"
    # CLI sends DriverOpts; some clients/inspect use Options. Check both.
    opts = cfg.get("DriverOpts") or cfg.get("Options") or {}
    if not vol_device_ok(opts.get("device")):
        return "volume binds host path outside workspace: " + opts.get("device", "")
    return None


def create_net_refs(cfg):
    """Networks a create body would join, for the membership backstop. `host` and
    `container:` shares are already denied by check_create, so they never reach here;
    we only need the named/id refs that check_create's suffix+cache check could miss
    (e.g. the gate joined by raw/short network id)."""
    hc = cfg.get("HostConfig") or {}
    refs = set()
    nm = hc.get("NetworkMode") or ""
    if nm and nm != "host" and not nm.startswith("container:"):
        refs.add(nm)
    for net in (cfg.get("NetworkingConfig") or {}).get("EndpointsConfig") or {}:
        refs.add(net)
    return refs


def create_vol_refs(cfg):
    """Named volumes a create body mounts BY REFERENCE (Type=volume, Source set, no
    inline DriverConfig -- those are caught purely by check_create). These names are
    resolved against the daemon in the backstop, mirroring create_net_refs: a host-
    bind local volume created out-of-band (e.g. before this gate shipped) would
    otherwise be mountable by name with no inline opts for check_create to see."""
    refs = set()
    for m in (cfg.get("HostConfig") or {}).get("Mounts") or []:
        if m.get("Type") == "volume":
            src = m.get("Source")
            if src and not ((m.get("VolumeOptions") or {}).get("DriverConfig")):
                refs.add(src)
    return refs


def volume_is_hostbind(name):
    """True only if volume `name` POSITIVELY resolves to a host-bind local volume
    whose device is outside the workspace. An unknown/absent volume returns False:
    the daemon will create it fresh and plain, and the volume-create gate already
    blocks making a bind volume through the shim -- so a missing name is not a bind."""
    try:
        data = http_get_json("/volumes/%s" % name)
    except Exception:
        return False
    return not vol_device_ok((data.get("Options") or {}).get("device"))


def target_is_ours(cid):
    try:
        data = http_get_json("/containers/%s/json" % cid)
        return ((data.get("Config") or {}).get("Labels") or {}).get(OWN_LABEL) == "1"
    except Exception:
        return False                           # fail closed


# ---- HTTP plumbing ----------------------------------------------------------
def read_headers(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def content_length(head):
    for l in head.split(b"\r\n"):
        if l.lower().startswith(b"content-length:"):
            try:
                return int(l.split(b":", 1)[1])
            except Exception:
                return None
    return None


def set_content_length(head, n):
    lines = [l for l in head.split(b"\r\n") if not l.lower().startswith(b"content-length:")]
    return b"\r\n".join(lines + [b"Content-Length: %d" % n])


def is_upgrade(head):
    """True if this is a connection-hijack request (Docker `exec start`/`attach`
    streaming). The CLI/dockerode send `Connection: Upgrade` + `Upgrade: tcp` and
    expect a 101; we must NOT rewrite those headers or the handshake breaks (502)."""
    for l in head.split(b"\r\n")[1:]:
        ll = l.lower()
        if ll.startswith(b"upgrade:"):
            return True
        if ll.startswith(b"connection:") and b"upgrade" in ll:
            return True
    return False


def rewrite(head, upgrade=False):              # force one request per connection
    # Hijack/upgrade requests pass through verbatim so the handshake survives;
    # relay() then carries the raw bidirectional stream until EOF.
    if upgrade:
        return head + b"\r\n\r\n"
    lines = head.split(b"\r\n")
    kept = [l for l in lines[1:] if not l.lower().startswith((b"connection:", b"keep-alive:"))]
    return b"\r\n".join([lines[0]] + kept + [b"Connection: close"]) + b"\r\n\r\n"


def deny(sock, msg):
    body = json.dumps({"message": "denied by authz shim: " + msg}).encode()
    sock.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n"
                 b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
    print("DENY:", msg, flush=True)


def relay(a, b):
    socks = [a, b]
    while socks:
        for s in select.select(socks, [], [])[0]:
            data = s.recv(65536)
            other = b if s is a else a
            if not data:
                socks.remove(s)
                try:
                    other.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            else:
                other.sendall(data)


def handle(client):
    try:
        head, rest = read_headers(client)
        if not head:
            return
        parts = head.split(b"\r\n", 1)[0].split(b" ")
        if len(parts) < 2:
            return
        method, path = parts[0], parts[1].decode("latin1")
        body = rest

        mc = CONNECT_RE.match(path)
        m = EXEC_RE.match(path)
        ma = ATTACH_RE.match(path)
        mar = ARCHIVE_RE.match(path)
        mvc = VOLCREATE_RE.match(path)
        if mar:
            # GET = `docker cp` out (exfiltrate), PUT = `docker cp` in (inject).
            # Gate BOTH by ownership, regardless of method.
            if not target_is_ours(mar.group(2)):
                return deny(client, "archive (docker cp) a container we don't own")
        elif method == b"POST" and mvc:
            clen = content_length(head)
            if clen is None:
                return deny(client, "volume create without Content-Length")
            while len(body) < clen:
                chunk = client.recv(65536)
                if not chunk:
                    break
                body += chunk
            reason = check_volume_create(body[:clen])
            if reason:
                return deny(client, reason)
            print("ALLOW: volume create", flush=True)
        elif method == b"POST" and mc:
            net = mc.group(2)
            if is_gate_net(net) or network_is_gate(net):
                return deny(client, "connect a container to the gate network: " + net)
        elif method == b"POST" and m:
            if not target_is_ours(m.group(2)):
                return deny(client, "exec into a container we don't own")
        elif method == b"POST" and ma:
            # attach streams (and can write) a container's I/O -- same risk class as
            # exec, so gate it identically. Without this, enabling upgrade passthrough
            # (below) would let the dev container attach to ANY host container.
            if not target_is_ours(ma.group(2)):
                return deny(client, "attach to a container we don't own")
        elif method == b"POST" and CREATE_RE.match(path):
            clen = content_length(head)
            if clen is None:
                return deny(client, "create without Content-Length")
            while len(body) < clen:
                chunk = client.recv(65536)
                if not chunk:
                    break
                body += chunk
            reason = check_create(body[:clen])
            if reason:
                return deny(client, reason)
            cfg = json.loads(body[:clen])
            # Membership backstop, identical to the `network connect` gate: the
            # suffix+cache check in check_create can miss a gate joined by raw/short
            # network id (a 12-char id has no `_gate` suffix and isn't an exact cache
            # member -- it's only a *prefix* of the full id we discovered). Resolve
            # each joined network against the daemon and deny if it hosts the proxy.
            for net in create_net_refs(cfg):
                if network_is_gate(net):
                    return deny(client, "joins the gate network: " + net)
            # Membership backstop for volumes, mirroring the network one: a named
            # volume mounted by reference (no inline opts for check_create to see)
            # could be a pre-existing host-bind local volume. Resolve each against
            # the daemon and deny if it binds a host path outside the workspace.
            for vol in create_vol_refs(cfg):
                if volume_is_hostbind(vol):
                    return deny(client, "mounts a host-bind volume: " + vol)
            cfg.setdefault("Labels", {})[OWN_LABEL] = "1"     # stamp ownership
            body = json.dumps(cfg).encode()
            head = set_content_length(head, len(body))
            print("ALLOW: create (owned)", flush=True)

        u = upstream()
        u.sendall(rewrite(head, is_upgrade(head)) + body)
        relay(client, u)
        u.close()
    except Exception:
        pass
    finally:
        client.close()


def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN)
    srv.listen(128)
    print("authz shim up -> %s:%d | allowed binds: %s | gate pattern: %s"
          % (UP_HOST, UP_PORT, ALLOWED, GATE_RE.pattern), flush=True)
    # Discover the gate network up front so a join-by-raw-id is caught from the
    # very first request (the suffix pattern alone wouldn't catch a raw id). The
    # upstream proxy may not be reachable the instant we start, so retry briefly.
    for _ in range(20):
        if gate_ids():
            break
        time.sleep(0.5)
    else:
        print("WARNING: gate network not discovered yet; until it is, only the "
              "suffix pattern guards join-by-id (raw-id joins/connects to a gate "
              "network created with a non-matching name could slip through)",
              flush=True)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
