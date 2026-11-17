import std/[httpclient, json, logging, net, options, sets, strformat, strutils, uri]

# TODO: support CIDRs
func parseIp*(str: string): Option[IpAddress] =
  try:
    let ip = str.strip().parseIpAddress()
    some(ip)
  except ValueError:
    none(IpAddress)

func isValidUrl*(url: string): bool =
  let uri = url.parseUri()
  return uri.scheme in ["http", "https"] and uri.isAbsolute()

proc download*(http: HttpClient, url: string): string =
  debug(fmt"Downloading IP feed at {url}")
  let response = http.request(url, httpMethod = HttpGet)
  defer:
    http.close()

  case response.code()
  of Http200:
    return response.body()
  else:
    raise newException(
      HttpRequestError, fmt"HTTP request failed with code: {response.code()}"
    )

func ipsFromJson*(node: JsonNode): HashSet[IpAddress] =
  var ips = initHashSet[IpAddress]()

  func walk(node: JsonNode) =
    case node.kind
    of JString:
      let parsedIp = node.str.parseIp()
      if parsedIp.isSome():
        ips.incl(parsedIp.get())
    of JArray:
      for i in node.items:
        walk(i)
    of JObject:
      for _, v in node:
        walk(v)
    else:
      discard

  node.walk()
  return ips

func ipsFromPlain*(body: string): HashSet[IpAddress] =
  for line in body.splitLines():
    let ip = line.parseIp()
    if ip.isSome():
      result.incl(ip.get())

proc parseFeed*(body: string): HashSet[IpAddress] =
  let feed = body.strip()
  if feed.len == 0:
    return

  result =
    try:
      let json = feed.parseJson()
      debug("Parsing JSON feed")
      json.ipsFromJson()
    except JsonParsingError:
      debug("Parsing plain text feed")
      feed.ipsFromPlain()
