
# wg-vanity

Fast WireGuard vanity key generator.
Finds private keys whose public keys start with a selected prefix.

## Usage

 - `-` matches `[+/]` (two base64 separators)
 - `?` matches any digit `0-9`

```bash
# Build
make

# Usage
./wg-vanity <prefix> [count]

# Examples
./wg-vanity test     # Find a key whose public key starts with "test"
./wg-vanity abc 5    # Generate 5 keys starting with "abc"
./wg-vanity 'w??-'   # matches w00/, w01+, w99/, etc.
```

Output: `<public_key> <private_key>` (one pair per line, keys to stdout, progress to stderr).

