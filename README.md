# Deceptimeed

> **Meed** (/miːd/), *n.*  
> 1 : *an earned reward or wage*  
> 2 : *a fitting return or recompense*

This is a utility program for loading IP blocklists into `nftables` from HTTP endpoints exposing plain text or JSON feeds. While primarily meant as a companion helper to [Deceptifeed](https://github.com/r-smith/deceptifeed) and its `/plain` and `/json` endpoints, it should be able to support any source feed as long as either of the following criteria are met: 

+ Plain text with one IP address per line
+ JSON data with IPs as string values

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
---

## Installation

`nim c -d:release -d:ssl src/deceptimeed.nim`

## Usage

```bash
deceptimeed <feed-url>
```

Requires root or `CAP_NET_ADMIN`.

## Testing

To test if an IP is successfully blocked, you can simulate spoofed traffic using tools like `hping3`. For example, to test blocking of `1.2.3.4` (assuming it's in your blocklist):

```bash
hping3 -S -a 1.2.3.4 <your-server-ip>
```

Replace `<your-server-ip>` with the IP of the machine using `deceptimeed`. The packet will be dropped silently if the blocking is effective.

---

## How It Works

1. **Ruleset Setup**  
   On first run, creates:
   - `table inet blocklist`
   - `set bad_ip4` (IPv4) and `set bad_ip6` (IPv6)
   - `chain preraw` with drop rules matching source addresses in those sets

2. **Feed Download**  
   Pulls a plaintext or JSON IP feed from a configured endpoint.

3. **Parsing and Filtering**  
   - Extracts IP addresses (IPv4 and IPv6).
   - Removes invalid entries and duplicates.
   - Caps total at 100 000 IPs (hard-coded for now).

4. **Atomic Update**  
   Replaces the contents of both sets using a single `nft -f` batch.  
   If the batch fails, the current set contents remain unchanged.

---

## Configuration

> [!WARNING]
> `nftables` names and parameters are currently hardcoded. Configuration support is planned.
