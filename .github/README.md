# Deceptimeed

> **Meed** (/miːd/), *n.*\
> 1 : *an earned reward or wage*\
> 2 : *a fitting return or recompense*

This is a utility program for loading IP blocklists into `nftables` from HTTP endpoints exposing plain text or JSON feeds. While primarily meant as a companion helper to [Deceptifeed](https://github.com/r-smith/deceptifeed) and its `/plain` and `/json` endpoints, it should be able to support any source feed as long as either of the following criteria are met:

- Plain text with one IP address per line
- JSON data with IPs as string values

## Example feeds

**Plain text**:

```plain
244.38.32.145
208.206.100.55
216.94.57.114
```

**JSON**:

```json
{
  "threat_feed": [
    {
      "ip": "244.38.32.145",
      "added": "2025-04-18T16:53:25.633864571Z",
      "last_seen": "2025-04-19T12:44:40.711376448Z",
      "observations": 5
    },
    {
      "ip": "208.206.100.55",
      "added": "2025-04-18T17:26:01.135873822Z",
      "last_seen": "2025-04-18T17:26:01.135873822Z",
      "observations": 1
    },
    {
      "ip": "216.94.57.114",
      "added": "2025-04-19T04:17:29.122866189Z",
      "last_seen": "2025-04-19T04:17:29.122866189Z",
      "observations": 1
    },
  ]
}
```

> [!NOTE]
> The structure of the JSON data doesn't matter since the parser extracts any strings representing valid IP addresses.

______________________________________________________________________

## Installation

**Using Nimble**

```bash
nimble install deceptimeed
```

**Compiling from source**

```bash
nim c -d:release -d:ssl src/deceptimeed.nim
```

## Usage

*Requires root.*

```bash
Usage:
  deceptimeed [options] feed_url

Arguments:
  feed_url         IP feed URL

Options:
  -h, --help
  --version                  Show program version and exit
  -c, --config=CONFIG        Path to config file (default: /etc/deceptimeed.conf)
```

**Example:**

```bash
deceptimeed -c /etc/custom.conf https://honeypot.mydomain.com/plain
```

## Testing

To test if an IP is successfully blocked, you can simulate traffic using tools like `hping3`. For example, to test blocking of `1.2.3.4` (assuming it's in your blocklist):

```bash
hping3 -S -a 1.2.3.4 <your-server-ip>
```

Replace `<your-server-ip>` with the IP of the machine using `deceptimeed`. The packet will be dropped silently if the blocking is effective.

______________________________________________________________________

## How It Works

1. **Ruleset Setup**\
   On first run, creates:

   - `table inet blocklist`
   - `set bad_ip4` (IPv4) and `set bad_ip6` (IPv6)
   - `chain preraw` with drop rules matching source addresses in those sets

1. **Feed Download**\
   Pulls a plaintext or JSON IP feed from a configured endpoint.

1. **Parsing and Filtering**

   - Extracts IP addresses (IPv4 and IPv6).
   - Removes invalid entries and duplicates.
   - Caps total at 100 000 IPs by default.

1. **Atomic Update**\
   Replaces the contents of both sets using a single `nft -f` batch.\
   If the batch fails, the current set contents remain unchanged.

______________________________________________________________________

## Configuration

The config file (default: `/etc/deceptimeed.conf`) supports these sections and options:

```ini
[nftables]
table = blocklist       ; Table name
set4 = bad_ip4          ; IPv4 set name  
set6 = bad_ip6          ; IPv6 set name
chain = preraw          ; Chain name
priority = -300         ; Chain priority
max_elements = 100000   ; Max IPs to process

[http]
timeout_ms = 10000      ; HTTP request timeout in milliseconds
```

The above defaults will be used in place of missing values or in the absence of a config file.
