import std/[net, os, parsecfg, posix, strformat, strutils, uri]
import ./deceptimeed/[config, feed, nft]
import pkg/argparse

const version = staticRead("../deceptimeed.nimble").newStringStream.loadConfig
  .getSectionValue("", "version")

func isValidUrl*(url: string): bool =
  return url.parseUri().isAbsolute

template buildParser*(): untyped =
  newParser("deceptimeed"):
    help("Load IP blocklists into nftables")

    arg("feed_url", help = "IP feed URL")
    flag("--version", help = "Show program version and exit", shortcircuit = true)
    option(
      "-c", "--config", help = "Path to config file (default: /etc/deceptimeed.conf)"
    )

proc main() =
  var parser = buildParser()
  let args =
    try:
      parser.parse()
    except ShortCircuit as e:
      if e.flag == "argparse_help":
        echo e.help
        quit(0)
      if e.flag == "version":
        echo version
        quit(0)
      else:
        raise
    except UsageError as e:
      echo fmt"Error parsing arguments: {e.msg}"
      quit(1)

  if getuid() != Uid(0):
    quit("Must run as root", 1)
  if not args.feedUrl.isValidUrl():
    quit(fmt"Invalid url: {args.feedUrl}", 1)

  let cfg = args.config_opt.get(otherwise = "").parseOrDefault()

  if "Error" in nftTable(cfg):
    ensureRuleset(cfg)

  let
    raw = args.feedUrl.download(cfg)
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

when isMainModule:
  main()
