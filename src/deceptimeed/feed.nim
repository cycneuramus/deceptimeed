import std/[httpclient, json, logging, net, sequtils, strformat, strutils, uri]

# TODO: redundant on account of IP parsing in 'splitIps'
template baseIp(s: string): string =
  s.split("/", 1)[0]

# TODO: redundant on account of IP parsing 'splitIps'
template isIp*(s: string): bool =
  try:
    discard parseIpAddress(s.baseIp)
    true
  except ValueError:
    false

template isJson(body: string): bool =
  body[0] in {'{', '['}

func isValidUrl*(url: string): bool =
  let uri = url.parseUri()
  return uri.scheme in ["http", "https"] and uri.isAbsolute

proc download*(http: HttpClient, url: string): string =
  debug(fmt"Downloading IP feed at {url}")
  http.getContent(url)

func diff*(feedIps, nftIps: seq[string]): seq[string] =
  feedIps.filterIt(it notin nftIps)

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

# TODO: separate out IP parsing concerns
proc splitIps*(ips: seq[string]): (seq[string], seq[string]) =
  var v4, v6: seq[string]
  for ip in ips:
    let parsedIp =
      try:
        parseIpAddress(ip.baseIp)
      except ValueError:
        continue

    case parsedIp.family
    of IPv4:
      v4.add($parsedIp)
    of IPv6:
      v6.add($parsedIp)

  result = (v4, v6)

proc parseFeed*(body: string): seq[string] =
  let feed = body.strip()
  if feed.len == 0:
    return

  if feed.isJson:
    debug("Parsing JSON feed")
    var ips: seq[string]
    ingestJson(parseJson(feed), ips)
    result = ips.deduplicate()
  else:
    debug("Parsing plain text feed")
    result = feed.splitLines.filterIt(it.strip().isIp).deduplicate()
