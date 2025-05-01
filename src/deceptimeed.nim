import
  std/[httpclient, json, net, os, osproc, posix, sequtils, strformat, strutils, uri]

const
  tbl* = "blocklist"
  set4* = "bad_ip4"
  set6* = "bad_ip6"
  chain = "preraw"
  prio = "-300"
  tmpFile = "/run/deceptimeed.nft"
  maxElems = 100_000

proc getFeedUrl(): string =
  if paramCount() != 1:
    quit("usage: deceptimeed <url>", 1)

  let url = paramStr(1).strip
  if not url.parseUri().isAbsolute:
    quit("invalid URL", 1)

  return url

proc run(cmd: string, args: seq[string]): int =
  let p = startProcess(cmd, args = args, options = {poUsePath})
  defer:
    p.close()

  p.waitForExit()

proc nft(batch: string): bool =
  writeFile(tmpFile, batch)
  run("nft", @["-f", tmpFile]) == 0

proc ensureRuleset() =
  if run("nft", @["list", "table", "inet", tbl]) == 0:
    return

  let boot =
    """
    add table inet $1
    add set   inet $1 $2 { type ipv4_addr; flags interval; comment "Deceptimeed"; }
    add set   inet $1 $3 { type ipv6_addr; flags interval; comment "Deceptimeed"; }
    add chain inet $1 $4 { type filter hook prerouting priority $5; policy accept; }
    add rule  inet $1 $4 ip  saddr @$2 drop
    add rule  inet $1 $4 ip6 saddr @$3 drop
  """ %
    [tbl, set4, set6, chain, prio]
  if not nft(boot):
    quit("bootstrap failed (nft error)", 1)

template isJson(body: string): bool =
  body[0] in {'{', '['}

template baseIp(s: string): string =
  s.split("/", 1)[0]

template isIp*(s: string): bool =
  try:
    discard parseIpAddress(s.baseIp)
    true
  except ValueError:
    false

func parsePlain*(body: string): seq[string] =
  for ln in body.splitLines:
    let trimmed = ln.strip
    if trimmed.isIp:
      result.add(trimmed)
  result = result.deduplicate

func parseJson(node: JsonNode, ips: var seq[string]) =
  case node.kind
  of JString:
    if node.str.isIp:
      ips.add(node.str)
  of JArray:
    for i in node.items:
      parseJson(i, ips)
  of JObject:
    for _, v in node:
      parseJson(v, ips)
  else:
    discard

proc processFeed*(body: string): seq[string] =
  let trimmed = body.strip
  if trimmed.len > 0 and trimmed.isJson:
    var ips: seq[string]
    parseJson(parseJson(trimmed), ips)
    ips.deduplicate
  else:
    parsePlain(body)

proc splitIps*(ips: seq[string]): (seq[string], seq[string]) =
  var v4, v6: seq[string]
  for ip in ips:
    try:
      if parseIpAddress(ip.baseIp).family == IPv4:
        v4.add(ip)
      else:
        v6.add(ip)
    except ValueError:
      discard

  result = (v4, v6)

func buildBatch*(ips: seq[string]): string =
  result =
    "flush set inet " & tbl & " " & set4 & "\n" & "flush set inet " & tbl & " " & set6 &
    "\n"
  let (ips4, ips6) = splitIps(ips)
  if ips4.len > 0:
    result &= "add element inet " & tbl & " " & set4 & " { " & ips4.join(", ") & " }\n"
  if ips6.len > 0:
    result &= "add element inet " & tbl & " " & set6 & " { " & ips6.join(", ") & " }\n"

when isMainModule:
  if getuid() != Uid(0):
    quit("must run as root or with CAP_NET_ADMIN", 1)

  ensureRuleset()

  let feedUrl = getFeedUrl()
  let raw = newHttpClient(timeout = 10_000).getContent(feedUrl)
  let ips = processFeed(raw)

  if ips.len > maxElems:
    quit("IP feed too large", 1)
  if not ips.len > 0:
    quit("no IPs to add", 0)

  let batch = buildBatch(ips)
  if not nft(batch):
    quit("nft load failed", 1)
  echo(fmt"{ips.len} IPs in blocklist")
