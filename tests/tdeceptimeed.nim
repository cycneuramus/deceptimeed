import std/[strutils, unittest]
import ../src/deceptimeed

suite "core helpers":
  test "isIp":
    check "1.2.3.4".isIp
    check "2001:db8::1".isIp
    check not "999.999.999.999".isIp

  test "plain feed":
    let ips = "1.1.1.1\ntrash\n2.2.2.2\n1.1.1.1\n"
    check parsePlain(ips) == @["1.1.1.1", "2.2.2.2"]

  test "JSON feed":
    let json = """{ "a": "10.0.0.1","b": ["dead:beef::1", {"x":"8.8.8.8"}] }"""
    check parseFeed(json) == @["10.0.0.1", "dead:beef::1", "8.8.8.8"]

  test "splitIps":
    let (v4, v6) = splitIps(@["1.1.1.1", "2001:db8::1", "8.8.8.8/32", "fd00::/8"])
    check v4 == @["1.1.1.1", "8.8.8.8/32"]
    check v6 == @["2001:db8::1", "fd00::/8"]

  test "invalid literals are ignored":
    let (v4, v6) = splitIps(@["not-an-ip", "300.300.300.300"])
    check v4.len == 0 and v6.len == 0

  test "batch builder":
    let batch = buildBatch(@["1.1.1.1", "dead:beef::1"])
    check batch.contains("flush set inet " & tbl & " " & set4)
    check batch.contains("flush set inet " & tbl & " " & set6)
    check batch.contains("{ 1.1.1.1 }")
    check batch.contains("{ dead:beef::1 }")

  test "empty batch":
    check buildBatch(@[]) ==
      "flush set inet " & tbl & " " & set4 & "\n" & "flush set inet " & tbl & " " & set6 &
      "\n"
