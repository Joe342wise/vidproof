# Python CLI Contract

Node invokes Python tools through subprocess calls. Each command writes one JSON object to stdout. Non-zero exits must still write a JSON error object when possible.

## Success Shape

```json
{
  "ok": true,
  "result": {}
}
```

## Error Shape

```json
{
  "ok": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable message"
  }
}
```

## Initial Commands

- `python forensics/hash_file.py <path>`
- `python forensics/verify_signature.py <public-key-base64> <hash-hex> <signature-base64>`
- `python forensics/prnu_compare.py <reference-path> <video-path>`
