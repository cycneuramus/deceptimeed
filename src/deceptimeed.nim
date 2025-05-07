import std/[logging, net, os, parsecfg, posix, strformat, strutils]
import ./deceptimeed/[config, feed, nft]
import pkg/argparse

const version = staticRead("../deceptimeed.nimble").newStringStream.loadConfig
  .getSectionValue("", "version")

template buildParser*(): untyped =
  newParser("deceptimeed"):
    help("Load IP blocklists into nftables")

    arg("feed_url", help = "IP feed URL")
    flag("--version", help = "Show program version and exit", shortcircuit = true)
    flag("-v", "--verbose", help = "Show detailed output")
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

  let
    logLevel = if args.verbose: lvlDebug else: lvlInfo
    logger = newConsoleLogger(
      fmtStr = "[$date $time]: [$levelname]: ", levelThreshold = logLevel
    )
  logger.addHandler()

  if getuid() != Uid(0):
    fatal("Must run as root")
    quit(1)
  if not args.feedUrl.isValidUrl():
    fatal(fmt"Invalid url: {args.feedUrl}")
    quit(1)

  let cfg = args.config_opt.get(otherwise = "/etc/deceptimeed.conf").parseOrDefault()

  debug("Checking for presence of ruleset")
  let nftState =
    try:
      nftState(cfg.table)
    except CatchableError as e:
      fatal(fmt"Failed to get nft table: {e.msg}")
      quit(1)

  # HACK: relying on nft output here is brittle
  if "Error" in nftState:
    info("Bootstrapping nftables ruleset")
    try:
      ensureRuleset(cfg)
    except CatchableError as e:
      quit(fmt"nft bootstrap failed: {e.msg}", 1)

  let
    raw = args.feedUrl.download(cfg)
    feedIps = parseFeed(raw)

  if feedIps.len > cfg.maxElems:
    fatal("IP feed too large")
    quit(1)
  if feedIps.len == 0:
    fatal("No IPs in feed")
    quit(1)

  let curIps =
    try:
      nftIps(nftState)
    except CatchableError as e:
      fatal(fmt"Failed to extract nft IPs: {e.msg}")
      quit(1)

  let newIps =
    try:
      feedIps.diff(curIps)
    except CatchableError as e:
      fatal(fmt"Failed to diff feed IPs from nftables IPs: {e.msg}")
      quit(1)

  if newIps.len == 0:
    info("No new IPs to add")
    quit(0)

  let batch = buildBatch(feedIps, cfg)
  try:
    batch.apply()
  except CatchableError as e:
    fatal(fmt"Failed to apply nftables batch: {e.msg}")
    quit(1)

  let totalIps = curIps.len + newIps.len
  info(fmt"{newIps.len} IPs added to blocklist ({totalIps} total)")

when isMainModule:
  main()
