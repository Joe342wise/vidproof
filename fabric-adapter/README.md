# Go Fabric Adapter

Thin HTTP service that wraps the official Hyperledger Fabric Gateway Go client.

The Python FastAPI backend calls this service instead of using a Python Fabric SDK. This keeps Fabric-specific code on an officially supported Go toolchain while leaving the main evidence workflow in Python.

Planned endpoints:

- `POST /camera/register`
- `POST /evidence/register`
- `POST /custody/log`
- `POST /verification/log`
- `GET /evidence/{id}/history`
