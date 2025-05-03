import std/[json, net, sequtils, strutils]

template baseIp(s: string): string =
  s.split("/", 1)[0]

template isIp*(s: string): bool =
  try:
    discard parseIpAddress(s.baseIp)
    true
  except ValueError:
    false

template isJson(body: string): bool =
  body[0] in {'{', '['}

func diff*(feedIps, nftIps: seq[string]): seq[string] =
  for ip in feedIps:
    if ip notin nftIps:
      result.add(ip)

func ingestJson*(node: JsonNode, ips: var seq[string]) =
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
