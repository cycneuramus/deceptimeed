import std/[files, paths, strformat, strutils, unittest]
import ../src/deceptimeed/[config, feed, nft]
import ../src/deceptimeed
import pkg/argparse

suite "CLI argument parsing":
  test "validate URL":
    let url = "https://honeypot.mydomain.com/plain"
    check isValidUrl(url) == true

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

suite "config":
  test "Fall back to default config":
    let cfg = parseOrDefault("/etc/non-existing-file")
    check cfg == defaultConfig

  test "Load config from file":
    let tmp = "test.conf"
    tmp.writeFile(
      """
        [nftables]
        table = "myblock"
        set4 = "ipv4_blacklist"
        set6 = "ipv6_blacklist"
        chain = "input_hook"
        priority = "-200"
        max_elements = "50000"

        [http]
        timeout_ms = "50000"
      """.dedent()
    )
    defer:
      tmp.Path().removeFile()

    let cfg = tmp.parseOrDefault()
    check cfg.table == "myblock"
    check cfg.set4 == "ipv4_blacklist"
    check cfg.set6 == "ipv6_blacklist"
    check cfg.chain == "input_hook"
    check cfg.prio == "-200"
    check cfg.maxElems == 50000
    check cfg.httpTimeoutMs == 50000

suite "feed":
  test "Is IP address":
    check "1.2.3.4".isIp
    check "2001:db8::1".isIp
    check not "999.999.999.999".isIp
    check "10.0.0.0/24".isIp
    check "2001:db8::/32".isIp

  test "Plain feed":
    let ips = "1.1.1.1\ntrash\n2.2.2.2\n1.1.1.1\n"
    check parseFeed(ips) == @["1.1.1.1", "2.2.2.2"]

  test "Plain feed with line feeds":
    let ips = "1.1.1.1\r\ntrash\r\n2.2.2.2\r\n1.1.1.1\r\n"
    check parseFeed(ips) == @["1.1.1.1", "2.2.2.2"]

  test "JSON feed":
    let json = """{ "a": "10.0.0.1","b": ["dead:beef::1", {"x":"8.8.8.8"}] }"""
    check parseFeed(json) == @["10.0.0.1", "dead:beef::1", "8.8.8.8"]

  test "JSON feed with leading whitespace":
    let json = "\n  [\"1.1.1.1\", \"2.2.2.2\", \"1.1.1.1\"]"
    check parseFeed(json) == @["1.1.1.1", "2.2.2.2"]

  test "Split IPs into v4, v6":
    let (v4, v6) = splitIps(@["1.1.1.1", "2001:db8::1", "8.8.8.8/32", "fd00::/8"])
    check v4 == @["1.1.1.1", "8.8.8.8/32"]
    check v6 == @["2001:db8::1", "fd00::/8"]

  test "Invalid entries are ignored":
    let (v4, v6) = splitIps(@["not-an-ip", "300.300.300.300"])
    check v4.len == 0 and v6.len == 0

suite "nft":
  let cfg = config.parseOrDefault("/etc/deceptimeed.conf")

  test "Build batch":
    let batch = buildBatch(@["1.1.1.1", "dead:beef::1"], cfg)
    check batch.contains(fmt"flush set inet {cfg.table} {cfg.set4}")
    check batch.contains(fmt"flush set inet {cfg.table} {cfg.set6}")
    check batch.contains("{ 1.1.1.1 }")
    check batch.contains("{ dead:beef::1 }")

  test "Empty batch":
    check buildBatch(@[], cfg) ==
      fmt"""
        flush set inet {cfg.table} {cfg.set4}
        flush set inet {cfg.table} {cfg.set6}
      """.dedent

  test "Extract nftables IPs":
    let mockNftOutput =
      """
        {
          "nftables": [
            {
              "metainfo": {
                "version": "1.0.6",
                "release_name": "Lester Gooch #5",
                "json_schema_version": 1
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
                "flags": [
                  "interval"
                ],
                "elem": [
                  "1.2.3.4",
                  "5.6.7.8",
                  "192.168.0.1"
                ]
              }
            }
          ]
        }
      """.dedent

    check nftIps(mockNftOutput) == ["1.2.3.4", "5.6.7.8", "192.168.0.1"]

  test "Yield only new IPs":
    let feedIps = @["10.0.0.1", "192.168.0.1", "203.0.113.5"]
    let nftIps = @["192.168.0.1", "198.51.100.7"]
    let newIps = feedIps.diff(nftIps)
    check newIps == @["10.0.0.1", "203.0.113.5"]
