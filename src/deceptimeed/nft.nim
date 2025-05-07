import std/[json, logging, os, osproc, strformat, strutils, tempfiles]
import ./[config, feed]

proc run*(cmd: string, args: seq[string]): string =
  debug(&"Running cmd: {cmd} {args.join(\" \")}")
  # TODO: check exit status
  execProcess(command = cmd, args = args, options = {poUsePath, poStdErrToStdOut})

proc nftState*(tbl: string): string =
  debug(fmt"Getting nft table '{tbl}'")
  run("nft", @["-j", "list", "table", "inet", tbl])

proc nftIps*(nftOutput: string): seq[string] =
  var ips: seq[string]
  ingestJson(parseJson(nftOutput), ips)
  result = ips

proc apply*(batch: string) =
  let (tmpF, tmpFp) = createTempFile("deceptimeed", "")
  defer:
    tmpFp.removeFile()
  tmpF.write(batch)
  tmpF.close()

  discard run("nft", @["-f", tmpFp])

proc ensureRuleset*(cfg: Config) =
  let bootstrap =
    """
      add table inet $1
      add set   inet $1 $2 { type ipv4_addr; flags interval; comment "Deceptimeed"; }
      add set   inet $1 $3 { type ipv6_addr; flags interval; comment "Deceptimeed"; }
      add chain inet $1 $4 { type filter hook prerouting priority $5; policy accept; }
      add rule  inet $1 $4 ip  saddr @$2 drop
      add rule  inet $1 $4 ip6 saddr @$3 drop
    """.dedent %
    [cfg.table, cfg.set4, cfg.set6, cfg.chain, cfg.prio]

  bootstrap.apply()

func buildBatch*(ips: seq[string], cfg: Config): string =
  result =
    fmt"""
      flush set inet {cfg.table} {cfg.set4}
      flush set inet {cfg.table} {cfg.set6}
    """.dedent

  let (ips4, ips6) = splitIps(ips)
  if ips4.len > 0:
    result.add(&"add element inet {cfg.table} {cfg.set4} {{ {ips4.join(\", \")} }}\n")
  if ips6.len > 0:
    result.add(&"add element inet {cfg.table} {cfg.set6} {{ {ips6.join(\", \")} }}\n")
