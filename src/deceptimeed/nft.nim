import
  std/
    [json, logging, net, os, osproc, sequtils, streams, strformat, strutils, tempfiles]
import ./[config, feed]

const nftCmd = "nft"

type NftError* = object of CatchableError

proc nft*(args: seq[string]): string =
  debug(&"Running cmd: {nftCmd} {args.join(\" \")}")
  let process =
    startProcess(nftCmd, args = args, options = {poUsePath, poStdErrToStdOut})
  defer:
    process.close()

  result = process.outputStream().readAll()
  let exitCode = process.waitForExit()

  if exitCode != 0:
    raise newException(NftError, fmt"{nftCmd} exited with code {exitCode}: {result}")

proc state*(tbl: string): JsonNode =
  debug(fmt"Getting nft table '{tbl}'")
  let output = nft(@["-j", "list", "table", "inet", tbl])
  try:
    output.parseJson()
  except JsonParsingError:
    raise

proc apply*(batch: string) =
  let (tmpF, tmpFp) = createTempFile("deceptimeed", "")
  defer:
    tmpFp.removeFile()
  tmpF.write(batch)
  tmpF.close()

  discard nft(@["-f", tmpFp])

func buildRuleset*(cfg: Config): string =
  result =
    """
      add table inet $1
      add set   inet $1 $2 { type ipv4_addr; flags interval; comment "Deceptimeed"; }
      add set   inet $1 $3 { type ipv6_addr; flags interval; comment "Deceptimeed"; }
      add chain inet $1 $4 { type filter hook prerouting priority $5; policy accept; }
      add rule  inet $1 $4 ip  saddr @$2 drop
      add rule  inet $1 $4 ip6 saddr @$3 drop
    """.dedent() %
    [cfg.table, cfg.set4, cfg.set6, cfg.chain, cfg.prio]

func buildBatch*(addIps, delIps: seq[IpAddress], cfg: Config): string =
  let (del4, del6) = delIps.splitIps()
  let (add4, add6) = addIps.splitIps()

  if del4.len > 0:
    result.add(
      &"delete element inet {cfg.table} {cfg.set4} {{ {del4.mapIt($it).join(\", \")} }}\n"
    )
  if del6.len > 0:
    result.add(
      &"delete element inet {cfg.table} {cfg.set6} {{ {del6.mapIt($it).join(\", \")} }}\n"
    )
  if add4.len > 0:
    result.add(
      &"add element inet {cfg.table} {cfg.set4} {{ {add4.mapIt($it).join(\", \")} }}\n"
    )
  if add6.len > 0:
    result.add(
      &"add element inet {cfg.table} {cfg.set6} {{ {add6.mapIt($it).join(\", \")} }}\n"
    )
