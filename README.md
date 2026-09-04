# ztrapps

Example target/client apps for the ZTRelay network — reference implementations
of what you can run behind a relay tunnel, built on
[ztrclient](https://github.com/igenius21fm/ztrclient).

Each app comes in two halves: a **target** script (runs on the machine you're
tunneling into) and a matching **client** script (runs on your machine, talks
to the target through the relay).

| Target | Client | What it does |
|---|---|---|
| `ztr_requests.py` | `ztr_requests_client.py` | Makes real HTTP requests from the target's network position; the client gets back a `requests.Response`-like object. |
| `ztr_stream.py` | `ztr_stream_client.py` | Streams video files off the target's disk in fixed-size chunks — `list` and `get`, no transcoding or seeking. |
| `ztr_mailbox.py` | `ztr_mailbox_client.py` | A simple SecureDrop-style async drop-box: submit a message with no prior identity relationship, get a claim token back, check later for a reply. Unaudited reference implementation — review it yourself before relying on it for anything sensitive. |
| `ztr_worker_pool.py` | — | Runs a pool of relay-connected workers on one target for concurrent request handling. |

## Setup

These apps import `RelayClient` and `crypt_bot` from
[ztrclient](https://github.com/igenius21fm/ztrclient), resolved as a
**sibling directory named `ztrclient`** next to wherever this repo's files
live — not bundled here, so there's one copy to keep updated. That means the
folder holding these `.py` files and a folder called `ztrclient/` need a
common parent:

```bash
mkdir ztrelay && cd ztrelay
git clone https://github.com/igenius21fm/ztrapps.git apps

# then get ztrclient as a sibling of apps/ — download the latest release
# from https://github.com/igenius21fm/ztrclient/releases and unzip it here,
# or clone the repo and copy its inner ztrclient/ztrclient/ folder up to
# this level. Either way you should end up with:
#   ztrelay/apps/ztr_requests.py
#   ztrelay/ztrclient/ztrClient.py
#   ztrelay/ztrclient/utils/crypt_bot.py
```

Run ztrclient's installer first (it sets up a venv with the crypto
dependencies these apps also need), then run a target/client app with that
same interpreter, e.g.:

```bash
~/.local/share/ztr/venv/bin/python3 apps/ztr_requests.py
```

See the [ztrClient.py docs](https://your-ztrelay-instance/docs/ztrclient) for
the full walkthrough of each app, the `.ztr` config format, and setting up a
route between a target and a client.
