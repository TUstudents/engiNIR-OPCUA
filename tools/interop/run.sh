#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <build directory made by tools/interop/build.sh> [pytest arguments]" >&2
    exit 2
fi

build_dir=$(realpath "$1")
shift

port=62541
server_dll="$build_dir/Server/ConsoleReferenceServer.dll"
client_dll="$build_dir/Client/ConsoleReferenceClient.dll"
for dll in "$server_dll" "$client_dll"; do
    [ -f "$dll" ] || { echo "missing $dll, run tools/interop/build.sh first" >&2; exit 2; }
done
command -v dotnet >/dev/null || { echo "dotnet is not on PATH" >&2; exit 2; }
if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "port $port is already in use, the reference server needs it" >&2
    exit 2
fi

work_dir=$(mktemp -d)
server_log="$work_dir/reference-server.log"
server_pid=""

stop_server() {
    if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
        kill "$server_pid" 2>/dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "$server_pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "$server_pid" 2>/dev/null || true
    fi
}

cleanup() {
    stop_server
    if [ -n "${ENGINIR_INTEROP_KEEP_LOGS:-}" ]; then
        echo "reference server log kept in $server_log" >&2
    else
        rm -rf "$work_dir"
    fi
}
trap cleanup EXIT

data_home="$work_dir/data"
mkdir -p "$data_home"

(
    cd "$(dirname "$server_dll")"
    exec env DOTNET_CLI_TELEMETRY_OPTOUT=1 HOME="$data_home" XDG_DATA_HOME="$data_home" \
        dotnet "$server_dll" --autoaccept --console --timeout 3600 >"$server_log" 2>&1
) &
server_pid=$!

for _ in $(seq 1 120); do
    if grep -q "Server started" "$server_log" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        echo "the reference server exited early:" >&2
        cat "$server_log" >&2
        exit 1
    fi
    sleep 0.5
done
grep -q "Server started" "$server_log" || { echo "the reference server did not start in 60 s" >&2; cat "$server_log" >&2; exit 1; }

export ENGINIR_INTEROP_SERVER_URL="opc.tcp://localhost:$port/Quickstarts/ReferenceServer"
export ENGINIR_INTEROP_CLIENT_DLL="$client_dll"
export ENGINIR_INTEROP_REFERENCE_PKI="$data_home/OPC Foundation/pki"
export ENGINIR_INTEROP_DOTNET
ENGINIR_INTEROP_DOTNET=$(command -v dotnet)
export ENGINIR_INTEROP_WORK_DIR="$work_dir"

cd "$(dirname "$0")/../.."
uv run pytest -m interop tests/interop "$@"
