import std/[httpclient, json, logging, net, options, sequtils, strformat, strutils, uri]

# TODO: support CIDRs
template parseIp*(str: string): Option[IpAddress] =
  try:
    let ip = str.parseIpAddress()
    some(ip)
  except ValueError:
    none(IpAddress)

func isValidUrl*(url: string): bool =
  let uri = url.parseUri()
  return uri.scheme in ["http", "https"] and uri.isAbsolute

proc download*(http: HttpClient, url: string): string =
  debug(fmt"Downloading IP feed at {url}")
  http.getContent(url)

func diff*(feedIps, nftIps: seq[IpAddress]): seq[IpAddress] =
  feedIps.filterIt(it notin nftIps)

func jsonIps*(node: JsonNode): seq[IpAddress] =
  func walk(node: JsonNode, ips: var seq[IpAddress]) =
    case node.kind
    of JString:
      let parsedIp = node.str.parseIp()
      if parsedIp.isSome():
        ips.add(parsedIp.get())
    of JArray:
      for i in node.items:
        walk(i, ips)
    of JObject:
      for _, v in node:
        walk(v, ips)
    else:
      discard

  var ips: seq[IpAddress]
  node.walk(ips)

  return ips

func plainIps*(body: string): seq[IpAddress] =
  for line in body.splitLines():
    let ip = line.parseIp()
    if ip.isSome():
      result.add(ip.get())

proc splitIps*(ips: seq[IpAddress]): (seq[string], seq[string]) =
  var v4, v6: seq[string]
  for ip in ips:
    case ip.family
    of IPv4:
      v4.add($ip)
    of IPv6:
      v6.add($ip)

  result = (v4, v6)

proc parseFeed*(body: string): seq[IpAddress] =
  let feed = body.strip()
  if feed.len == 0:
    return

  result =
    try:
      let jfeed = feed.parseJson()
      debug("Parsing JSON feed")
      jfeed.jsonIps().deduplicate()
    except JsonParsingError:
      debug("Parsing plain text feed")
      feed.plainIps().deduplicate()
