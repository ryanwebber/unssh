# unssh - An [UN]-[S]ecure [SH]ell

This is a toy implementation of an ssh server that you should not use. It is
minimally functional, essentially just enough to connect and run a shell
on the host.

## Getting Started

Running the server:

```
# Generate a host key. Currently, only ed25519 is supported.
ssh-keygen -t ed25519 -f /path/to/keygen/output

# Run the ssh server
cargo run --release -- --host-key /path/to/keygen/output.pub --port 2222
```

Connecting to the server can be done with any ssh client. Currently there
is no support for authentication.
