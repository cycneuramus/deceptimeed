import std/[files, parsecfg, paths, strutils, with]

type Config* = object
  table*, set4*, set6*, chain*, prio*: string
  maxElems*, httpTimeoutMs*: int

const defaultConfig* = Config(
  table: "blocklist",
  set4: "bad_ip4",
  set6: "bad_ip6",
  chain: "preraw",
  prio: "-300",
  maxElems: 100_000,
  httpTimeoutMs: 10_000,
)

proc parseOrDefault*(cfgFile: string = "/etc/deceptimeed.conf"): Config =
  var cfg = defaultConfig
  if not cfgFile.Path().fileExists():
    return cfg

  let parser = cfgFile.loadConfig()
  with cfg:
    table = parser.getSectionValue("nftables", "table", "")
    set4 = parser.getSectionValue("nftables", "set4", "")
    set6 = parser.getSectionValue("nftables", "set6", "")
    chain = parser.getSectionValue("nftables", "chain", "")
    prio = parser.getSectionValue("nftables", "priority", "")
    maxElems = parser.getSectionValue("nftables", "max_elements", "").parseInt()
    httpTimeoutMs = parser.getSectionValue("http", "timeout_ms", "").parseInt()

  return cfg
