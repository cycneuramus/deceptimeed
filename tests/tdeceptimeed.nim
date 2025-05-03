import std/[strformat, strutils, unittest]
import ../src/deceptimeed

suite "core helpers":
  test "isIp":
    check "1.2.3.4".isIp
    check "2001:db8::1".isIp
    check not "999.999.999.999".isIp
    check "10.0.0.0/24".isIp
    check "2001:db8::/32".isIp

  test "plain feed":
    let ips = "1.1.1.1\ntrash\n2.2.2.2\n1.1.1.1\n"
    check parseFeed(ips) == @["1.1.1.1", "2.2.2.2"]

  test "plain feed with line feeds":
    let ips = "1.1.1.1\r\ntrash\r\n2.2.2.2\r\n1.1.1.1\r\n"
    check parseFeed(ips) == @["1.1.1.1", "2.2.2.2"]

  test "JSON feed":
    let json = """{ "a": "10.0.0.1","b": ["dead:beef::1", {"x":"8.8.8.8"}] }"""
    check parseFeed(json) == @["10.0.0.1", "dead:beef::1", "8.8.8.8"]

  test "JSON feed with leading whitespace":
    let json = "\n  [\"1.1.1.1\", \"2.2.2.2\", \"1.1.1.1\"]"
    check parseFeed(json) == @["1.1.1.1", "2.2.2.2"]

  test "splitIps":
    let (v4, v6) = splitIps(@["1.1.1.1", "2001:db8::1", "8.8.8.8/32", "fd00::/8"])
    check v4 == @["1.1.1.1", "8.8.8.8/32"]
    check v6 == @["2001:db8::1", "fd00::/8"]

  test "invalid literals are ignored":
    let (v4, v6) = splitIps(@["not-an-ip", "300.300.300.300"])
    check v4.len == 0 and v6.len == 0

  test "batch builder":
    let batch = buildBatch(@["1.1.1.1", "dead:beef::1"])
    check batch.contains(fmt"flush set inet {tbl} {set4}")
    check batch.contains(fmt"flush set inet {tbl} {set6}")
    check batch.contains("{ 1.1.1.1 }")
    check batch.contains("{ dead:beef::1 }")

  test "empty batch":
    check buildBatch(@[]) ==
      fmt"""
        flush set inet {tbl} {set4}
        flush set inet {tbl} {set6}
      """.dedent

  test "nftables IP set retrieval":
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

  test "feed vs nft yields only new IPs":
    let feedIps = @["10.0.0.1", "192.168.0.1", "203.0.113.5"]
    let nftIps = @["192.168.0.1", "198.51.100.7"]
    let newIps = feedIps.diff(nftIps)
    check newIps == @["10.0.0.1", "203.0.113.5"]
