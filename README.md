# navio-p2pmsg

Standalone TypeScript SDK for Navio's **p2pmsg** encrypted broadcast bus.
Connects straight to Navio P2P nodes (TCP in Node, WebSocket in the browser),
no full node, no Electrum. Application-agnostic: identity, addressing,
encryption, reliable delivery and pub/sub for any app built on the bus.

See `DESIGN.md` for the wire spec and layer design.
