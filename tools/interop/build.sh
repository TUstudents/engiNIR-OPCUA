#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <UA-.NETStandard checkout> <output directory>" >&2
    exit 2
fi

source_dir=$(realpath "$1")
output_dir=$(realpath -m "$2")

export CustomTestTarget=net8.0
export DOTNET_CLI_TELEMETRY_OPTOUT=1

for application in Server Client; do
    dotnet build "$source_dir/Applications/ConsoleReference$application/ConsoleReference$application.csproj" \
        --configuration Release --framework net8.0 --output "$output_dir/$application"
done
