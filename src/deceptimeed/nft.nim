import
  std/[
    json, logging, net, os, osproc, sequtils, sets, streams, strformat, strutils,
    tempfiles,
  ]
import ./config

const nftCmd* = "nft"

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
  nft(@["-j", "list", "table", "inet", tbl]).parseJson()

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

func buildBatch*(addIps, delIps: HashSet[IpAddress], cfg: Config): string =
  for (verb, ips) in [("delete", delIps), ("add", addIps)]:
    for (family, setName) in [(IPv4, cfg.set4), (IPv6, cfg.set6)]:
      let elems = ips.toSeq().filterIt(it.family == family).mapIt($it)
      if elems.len > 0:
        let list = elems.join(", ")
        result.add(&"{verb} element inet {cfg.table} {setName} {{ {list} }}\n")
