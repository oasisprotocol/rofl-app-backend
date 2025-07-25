# ROFL App Backend

A backend for [ROFL App], a web-based dashboard application for creating,
exploring, monitoring and interacting with Oasis ROFL (Runtime Offchain Logic)
apps.

## Usage

To run the local development environment using Docker Compose:

```bash
make start
```

- Backend available at: http://localhost:8899

## Features

- Store ROFL App artifacts (template data, `rofl.yaml`, `compose.yaml`).
- Build ROFL app ORC files and publish them in a ROFL ORC registry.
- Assist with deploying ROFL apps.

## About ROFL

[Oasis ROFL (Runtime Offchain Logic)] is a framework that enables augmenting
deterministic on-chain execution with verifiable off-chain applications.

[ROFL App]: https://github.com/oasisprotocol/rofl-app/
[Oasis ROFL (Runtime Offchain Logic)]: https://docs.oasis.io/build/rofl/
