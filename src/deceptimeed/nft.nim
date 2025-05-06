import std/[json, os, osproc, strformat, strutils, tempfiles]
import ./[config, feed]

proc run*(cmd: string, args: seq[string]): string =
  try:
    execProcess(command = cmd, args = args, options = {poUsePath, poStdErrToStdOut})
  except OSError as e:
    quit(fmt"Error executing command: {e.msg}", 1)

proc nftTable*(cfg: Config): string =
  run("nft", @["-j", "list", "table", "inet", cfg.table])

proc nftIps*(nftOutput: string): seq[string] =
  var ips: seq[string]
  ingestJson(parseJson(nftOutput), ips)
  result = ips

proc nft*(batch: string) =
  let (tmpF, tmpFp) =
    try:
      createTempFile("deceptimeed", "")
    except OSError as e:
      quit(fmt"Error creating tmp file: {e.msg}", 1)
  defer:
    tmpFp.removeFile

  try:
    tmpF.write(batch)
    tmpF.close
  except IOError as e:
    quit(fmt"Writing to tmp file failed: {e.msg}", 1)

  try:
    discard run("nft", @["-f", tmpFp])
  except OSError as e:
    quit(fmt"nft command failed: {e.msg}", 1)

proc ensureRuleset*(cfg: Config) =
  echo "Bootstrapping nftables ruleset"
  let boot =
    """
      add table inet $1
      add set   inet $1 $2 { type ipv4_addr; flags interval; comment "Deceptimeed"; }
      add set   inet $1 $3 { type ipv6_addr; flags interval; comment "Deceptimeed"; }
      add chain inet $1 $4 { type filter hook prerouting priority $5; policy accept; }
      add rule  inet $1 $4 ip  saddr @$2 drop
      add rule  inet $1 $4 ip6 saddr @$3 drop
    """.dedent %
    [cfg.table, cfg.set4, cfg.set6, cfg.chain, cfg.prio]
  try:
    nft(boot)
  except OSError as e:
    quit(fmt"nft bootstrap failed: {e.msg}", 1)

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
