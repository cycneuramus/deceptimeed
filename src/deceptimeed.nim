import
  std/[httpclient, json, logging, net, os, parsecfg, posix, sets, strformat, strutils]
import ./deceptimeed/[config, feed, nft]
import pkg/argparse

type
  Feed = object
    url: string
    client: HttpClient
    interval: int

  FeedError = object of CatchableError

const version = staticRead("../deceptimeed.nimble").newStringStream.loadConfig
  .getSectionValue("", "version")

template buildParser*(): untyped =
  newParser("deceptimeed"):
    help("Load IP blocklists into nftables")

    arg("feed_url", help = "IP feed URL")
    flag("--version", help = "Show program version and exit", shortcircuit = true)
    flag("--oneshot", help = "Run once and exit")
    flag("-v", "--verbose", help = "Show detailed output")
    option("-i", "--interval", help = "Minutes between refreshes", default = some("10"))
    option(
      "-c",
      "--config",
      help = "Path to config file",
      default = some("/etc/deceptimeed.conf"),
    )

proc refresh(feed: Feed, cfg: config.Config) =
  let
    body = feed.client.download(feed.url)
    feedIps = body.parseFeed()

  if feedIps.len == 0:
    info("No IPs in feed")
    return
  if feedIps.len > cfg.maxElems:
    raise
      newException(FeedError, fmt"IP feed exceeds maximum size of {cfg.maxElems} items")

  let
    nftState = cfg.table.state()
    curIps = nftState.ipsFromJson()
    addIps = difference(feedIps, curIps)
    delIps = difference(curIps, feedIps)

  if addIps.len == 0 and delIps.len == 0:
    debug("Blocklist unchanged")
    return

  let batch = buildBatch(addIps, delIps, cfg)
  if batch.len == 0:
    debug("No batch generated")
    return

  batch.apply()
  info(fmt"{addIps.len} IPs added, {delIps.len} removed – {feedIps.len} total")

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
  if not args.interval.parseInt() > 0:
    fatal(fmt"Invalid interval: {args.interval}")

  let
    cfg = args.config.parseOrDefault()
    client = newHttpClient(timeout = cfg.httpTimeoutMs)
    feed = Feed(
      url: args.feedUrl, client: client, interval: args.interval.parseInt() * 60 * 1000
    )

  debug("Checking for presence of ruleset")
  try:
    discard cfg.table.state()
    debug("Ruleset already present")
  except JsonParsingError, NftError:
    info("Bootstrapping nftables ruleset")
    try:
      let ruleset = buildRuleset(cfg)
      ruleset.apply()
    except CatchableError as e:
      fatal(fmt"Failed to bootstrap nftables ruleset: {e.msg}")
      quit(1)

  while true:
    try:
      feed.refresh(cfg)
    except FeedError, HttpRequestError, NftError:
      let e = getCurrentException()
      error(e.msg)
    except CatchableError as e:
      fatal(fmt"Refresh failed: {e.msg}")
      quit(1)

    if args.oneshot:
      break

    debug(fmt"Sleeping for {args.interval} minutes...")
    sleep(feed.interval)

when isMainModule:
  main()
