import
  std/[
    httpclient, json, net, os, osproc, posix, sequtils, strformat, strutils, tempfiles,
    uri,
  ]

const
  tbl* = "blocklist"
  set4* = "bad_ip4"
  set6* = "bad_ip6"
  chain = "preraw"
  prio = "-300"
  maxElems = 100_000

proc cliFeedUrl(): string =
  if paramCount() != 1:
    quit("Usage: deceptimeed <url>", 1)

  let url = paramStr(1).strip
  if not url.parseUri().isAbsolute:
    quit("Invalid URL", 1)

  return url

proc run(cmd: string, args: seq[string]): string =
  try:
    execProcess(command = cmd, args = args, options = {poUsePath, poStdErrToStdOut})
  except OSError as e:
    quit(fmt"Error executing command: {e.msg}", 1)

proc nft(batch: string) =
  let (tmpF, tmpFp) =
    try:
      createTempFile("deceptimeed", "")
    except OSError as e:
      quit(fmt"Error creating tmp file: {e.msg}", 1)
  defer:
    tmpFp.removeFile

  try:
    tmpF.write(batch)
    tmpF.close
  except IOError as e:
    quit(fmt"Writing to tmp file failed: {e.msg}", 1)

  try:
    discard run("nft", @["-f", tmpFp])
  except OSError as e:
    quit(fmt"nft command failed: {e.msg}", 1)

proc nftTable(): string =
  run("nft", @["-j", "list", "table", "inet", tbl])

proc ensureRuleset() =
  echo "Bootstrapping nftables ruleset"
  let boot =
    """
      add table inet $1
      add set   inet $1 $2 { type ipv4_addr; flags interval; comment "Deceptimeed"; }
      add set   inet $1 $3 { type ipv6_addr; flags interval; comment "Deceptimeed"; }
      add chain inet $1 $4 { type filter hook prerouting priority $5; policy accept; }
      add rule  inet $1 $4 ip  saddr @$2 drop
      add rule  inet $1 $4 ip6 saddr @$3 drop
    """.dedent %
    [tbl, set4, set6, chain, prio]
  try:
    nft(boot)
  except OSError as e:
    quit(fmt"nft bootstrap failed: {e.msg}", 1)

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

func ingestJson(node: JsonNode, ips: var seq[string]) =
  case node.kind
  of JString:
    if node.str.isIp:
      ips.add(node.str)
  of JArray:
    for i in node.items:
      ingestJson(i, ips)
  of JObject:
    for _, v in node:
      ingestJson(v, ips)
  else:
    discard

func diff*(feedIps, nftIps: seq[string]): seq[string] =
  for ip in feedIps:
    if ip notin nftIps:
      result.add(ip)

proc nftIps*(nftOutput: string): seq[string] =
  var ips: seq[string]
  ingestJson(parseJson(nftOutput), ips)
  result = ips

proc parseFeed*(body: string): seq[string] =
  let feed = body.strip
  if feed.len == 0:
    return

  if feed.isJson:
    var ips: seq[string]
    ingestJson(parseJson(feed), ips)
    result = ips.deduplicate
  else:
    result = feed.splitLines.filterIt(it.strip.isIp).deduplicate

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
    fmt"""
      flush set inet {tbl} {set4}
      flush set inet {tbl} {set6}
    """.dedent

  let (ips4, ips6) = splitIps(ips)
  if ips4.len > 0:
    result.add(&"add element inet {tbl} {set4} {{ {ips4.join(\", \")} }}\n")
  if ips6.len > 0:
    result.add(&"add element inet {tbl} {set6} {{ {ips6.join(\", \")} }}\n")

when isMainModule:
  if getuid() != Uid(0):
    quit("Must run as root", 1)

  if "Error" in nftTable():
    ensureRuleset()

  let
    feedUrl = cliFeedUrl()
    raw = newHttpClient(timeout = 10_000).getContent(feedUrl)
    feedIps = parseFeed(raw)

    tblState = nftTable()
    curIps = nftIps(tblState)
    newIps = feedIps.diff(curIps)

  if newIps.len == 0:
    quit("No new IPs to add", 0)

  if feedIps.len > maxElems:
    quit("IP feed too large", 1)
  if feedIps.len == 0:
    quit("No IPs in feed", 0)

  let batch = buildBatch(feedIps)
  try:
    nft(batch)
  except OSError as e:
    quit(fmt"nft load failed: {e.msg}", 1)

  let totalIps = curIps.len + newIps.len
  echo(fmt"{newIps.len} IPs added to blocklist ({totalIps} total)")
