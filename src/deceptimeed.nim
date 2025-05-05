import std/[httpclient, net, os, posix, strformat, strutils, uri]
import ./deceptimeed/[config, feed, nft]

func isValidUrl*(url: string): bool =
  return url.parseUri().isAbsolute

when isMainModule:
  if getuid() != Uid(0):
    quit("Must run as root", 1)
  if paramCount() != 1:
    quit("Usage: deceptimeed <url>", 1)

  let
    cfg = defaultConfig()
    feedUrl = paramStr(1).strip

  if not isValidUrl(feedUrl):
    quit("Invalid URL", 1)

  if "Error" in nftTable(cfg):
    ensureRuleset(cfg)

  let
    raw = newHttpClient(timeout = 10_000).getContent(feedUrl)
    feedIps = parseFeed(raw)

  if feedIps.len > cfg.maxElems:
    quit("IP feed too large", 1)
  if feedIps.len == 0:
    quit("No IPs in feed", 0)

  let
    tblState = nftTable(cfg)
    curIps = nftIps(tblState)
    newIps = feedIps.diff(curIps)

  if newIps.len == 0:
    quit("No new IPs to add", 0)

  let batch = buildBatch(feedIps, cfg)
  try:
    nft(batch)
  except OSError as e:
    quit(fmt"nft load failed: {e.msg}", 1)

  let totalIps = curIps.len + newIps.len
  echo(fmt"{newIps.len} IPs added to blocklist ({totalIps} total)")
