import std/[json, net, sequtils, sets, strformat, strutils, tempfiles, unittest]
import ../src/deceptimeed/[config, feed, nft]
import ../src/deceptimeed
import pkg/argparse

# Test helper: uses the real `parseIp` but returns only valid IPs to let tests
# use mixed (valid + garbage) data without Option-handling boilerplate
func mockIps(strs: seq[string]): HashSet[IpAddress] =
  for str in strs:
    let ip = str.parseIp()
    if ip.isSome():
      result.incl(ip.get())

suite "CLI argument parsing":
  test "Valid URL":
    let url = "https://honeypot.mydomain.com/plain"
    check isValidUrl(url) == true

  test "Invalid URL":
    let url = "ftps://honeypot.mydomain.com"
    check isValidUrl(url) == false

  var parser = buildParser()

  test "Short config option":
    let args = parser.parse(@["-c", "deceptimeed.conf", "https://mydomain.com"])
    check args.config_opt.get == "deceptimeed.conf"

  test "Long config option":
    let args = parser.parse(@["--config", "deceptimeed.conf", "https://mydomain.com"])
    check args.config_opt.get == "deceptimeed.conf"

  test "Missing argument":
    expect(UsageError):
      discard parser.parse(@[])

  test "Daemonize by default":
    let args = parser.parse(@["https://example.com"])
    check args.oneshot == false
    check args.interval == "10"

  test "Oneshot flag":
    let args = parser.parse(@["--oneshot", "https://example.com"])
    check args.oneshot

  test "Interval flag":
    let args = parser.parse(@["--interval", "5", "https://example.com"])
    check args.interval.parseInt() == 5

suite "config":
  test "Use defaults if no config file":
    let cfg = parseOrDefault("/etc/non-existing-file")
    check cfg == defaultConfig

  test "Use config file":
    let (tmpF, tmpFp) = createTempFile("deceptimeed-test", "")
    defer:
      tmpFp.removeFile()
    tmpF.write(
      """
        [nftables]
        table = myblock
        set4 = ipv4_blacklist
        set6 = ipv6_blacklist
        chain = input_hook
        priority = -200
        max_elements = 50000

        [http]
        timeout_ms = 50000
      """.dedent()
    )
    tmpF.close()

    let cfg = tmpFp.parseOrDefault()
    check cfg.table == "myblock"
    check cfg.set4 == "ipv4_blacklist"
    check cfg.set6 == "ipv6_blacklist"
    check cfg.chain == "input_hook"
    check cfg.prio == "-200"
    check cfg.maxElems == 50000
    check cfg.httpTimeoutMs == 50000

  test "Use defaults for missing values in config file":
    let (tmpF, tmpFp) = createTempFile("deceptimeed-test", "")
    defer:
      tmpFp.removeFile()
    tmpF.write(
      """
        [nftables]
        table = "custom"
        set6  = "ipv6_custom"
        priority = "-250"

        [http]
        # omitted
      """.dedent()
    )
    tmpF.close()

    let cfg = tmpFp.parseOrDefault()

    check cfg.table == "custom"
    check cfg.set6 == "ipv6_custom"
    check cfg.prio == "-250"
    check cfg.set4 == defaultConfig.set4
    check cfg.chain == defaultConfig.chain
    check cfg.maxElems == defaultConfig.maxElems
    check cfg.httpTimeoutMs == defaultConfig.httpTimeoutMs

suite "feed":
  test "Is IP address":
    check "1.2.3.4".parseIp().isSome()
    check "2001:db8::1".parseIp().isSome()
    check "999.999.999.999".parseIp().isNone()
    check "10.0.0.0/24".parseIp().isNone()
    check "2001:db8::/32".parseIp().isNone()

  test "Plain feed":
    let ips = "1.1.1.1\ntrash\n2.2.2.2\n1.1.1.1\n"
    check parseFeed(ips) == @["1.1.1.1", "2.2.2.2"].mockIps()

  test "Plain feed with line feeds":
    let ips = "1.1.1.1\r\ntrash\r\n2.2.2.2\r\n1.1.1.1\r\n"
    check parseFeed(ips) == @["1.1.1.1", "2.2.2.2"].mockIps()

  test "JSON feed":
    let json = """{ "a": "10.0.0.1","b": ["2001:db8::1", {"x":"8.8.8.8"}] }"""
    check parseFeed(json) == @["10.0.0.1", "2001:db8::1", "8.8.8.8"].mockIps()

  test "JSON feed with leading whitespace":
    let json = "\n  [\"1.1.1.1\", \"2.2.2.2\", \"1.1.1.1\"]"
    check parseFeed(json) == @["1.1.1.1", "2.2.2.2"].mockIps()

  test "Split IPs into v4, v6":
    let (v4, v6) = splitIps(
      @["1.1.1.1", "not-an-ip", "2001:db8::1", "8.8.8.8/32", "fd00::/8"].mockIps()
    )
    check v4 == @["1.1.1.1"].mockIps()
    check v6 == @["2001:db8::1"].mockIps()

  test "Invalid entries are ignored":
    let ips = @["not-an-ip", "300.300.300.300", "1.2.3.4"].mockIps()
    check ips == @["1.2.3.4"].mockIps()

suite "nft":
  let cfg = parseOrDefault("/etc/deceptimeed.conf")

  test "Build incremental batch":
    let
      addIps = @["1.1.1.1", "2001:db8::1"].mockIps()
      delIps = @["2.2.2.2", "3001:db8::1"].mockIps()
      batch = buildBatch(addIps, delIps, cfg)
      expected = fmt"""
        delete element inet {cfg.table} {cfg.set4} {{ 2.2.2.2 }}
        delete element inet {cfg.table} {cfg.set6} {{ 3001:db8::1 }}
        add element inet {cfg.table} {cfg.set4} {{ 1.1.1.1 }}
        add element inet {cfg.table} {cfg.set6} {{ 2001:db8::1 }}
      """.dedent()

    check batch == expected

  test "Empty batch":
    check buildBatch(initHashSet[IpAddress](), initHashSet[IpAddress](), cfg) == ""

  test "Extract nftables IPs":
    let mockNftOutput =
      %*{
        "nftables": [
          {
            "metainfo": {
              "version": "1.0.6",
              "release_name": "Lester Gooch #5",
              "json_schema_version": 1,
            }
          },
          {
            "set": {
              "family": "inet",
              "name": "bad_ip4",
              "table": "blocklist",
              "type": "ipv4_addr",
              "handle": 1,
              "comment": "Deceptimeed",
              "flags": ["interval"],
              "elem": ["1.2.3.4", "5.6.7.8", "192.168.0.1"],
            }
          },
        ]
      }

    check mockNftOutput.ipsFromJson() == @["1.2.3.4", "5.6.7.8", "192.168.0.1"].mockIps()

  test "Yield only new IPs":
    let feedIps = @["10.0.0.1", "192.168.0.1", "203.0.113.5"].mockIps()
    let nftIps = @["192.168.0.1", "198.51.100.7"].mockIps()
    let newIps = difference(feedIps, nftIps)
    check newIps == @["10.0.0.1", "203.0.113.5"].mockIps()
