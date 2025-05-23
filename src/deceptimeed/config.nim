import std/[files, logging, parsecfg, paths, strformat, strutils, with]

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

proc parseOrDefault*(cfgFile: string): Config =
  var cfg = defaultConfig
  if not cfgFile.Path().fileExists():
    debug(fmt"Config file not found at {cfgFile}, using defaults")
    return cfg

  let parser = cfgFile.loadConfig()
  with cfg:
    table = parser.getSectionValue("nftables", "table", defaultConfig.table)
    set4 = parser.getSectionValue("nftables", "set4", defaultConfig.set4)
    set6 = parser.getSectionValue("nftables", "set6", defaultConfig.set6)
    chain = parser.getSectionValue("nftables", "chain", defaultConfig.chain)
    prio = parser.getSectionValue("nftables", "priority", defaultConfig.prio)
    maxElems = parser
      .getSectionValue("nftables", "max_elements", $defaultConfig.maxElems)
      .parseInt()
    httpTimeoutMs = parser
      .getSectionValue("http", "timeout_ms", $defaultConfig.httpTimeoutMs)
      .parseInt()

  return cfg
