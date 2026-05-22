# go-mercury

Go implementation of [Cisco Mercury](https://github.com/cisco/mercury) TLS application fingerprinting.

Computes **Network Protocol Fingerprints (NPF)** from raw TLS ClientHello bytes and looks them up in the Mercury fingerprint database to identify the sending application — firefox, curl, python-requests, etc.

## Installation

```sh
go get github.com/Allod-Solutions/go-mercury
```

## Usage

### Compute a fingerprint

Pass the raw bytes from a TLS record (starting at the `ContentType` byte) as seen on the wire:

```go
import "github.com/Allod-Solutions/go-mercury"

fp := mercury.Fingerprint(rawTLSRecord)
// e.g. "(0303)(0303)[(c02b)(c02f)...][(0000)(...)(000a)(...)]"
```

Returns `""` when the input is not a valid TLS ClientHello.

### Identify the application

Download the Cisco Mercury fingerprint database (`fingerprint_db.json`) from the [cisco/mercury releases](https://github.com/cisco/mercury/releases) and load it once at startup:

```go
db := mercury.NewDB()
if err := db.Load("/path/to/fingerprint_db.json"); err != nil {
    log.Fatal(err)
}

fp := mercury.Fingerprint(rawTLSRecord)
if info, ok := db.Lookup(fp); ok {
    fmt.Printf("process=%s os=%s prevalence=%.0f%%\n",
        info.Process, info.OS, info.Prevalence*100)
}
```

`Lookup` returns the candidate with the highest prevalence. `LookupAll` returns every candidate sorted by decreasing prevalence.

## Fingerprint format

Follows the Mercury NPF specification for TLS:

```
(record_version)(hello_version)[(cs1)(cs2)...][(ext_type)(ext_data)...]
```

- All values are lowercase hex in parentheses.
- GREASE values (RFC 8701) are filtered from cipher suites and extensions.
- Extension data is included for extensions that carry meaningful implementation variation (SNI, supported_groups, signature_algorithms, ALPN, key_share, supported_versions, …). Other extensions appear as type-code only.

## License

MIT — see [LICENSE](LICENSE).
