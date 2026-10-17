#!/bin/bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
trap 'unset OPENAI_API_KEY' EXIT
printf 'This experiment sends 70 API requests using your API account with the default repetition count.\n'
if [[ -z "${OPENAI_API_KEY:-}" ]]; then
  read -r -s -p 'API key (hidden; do not paste it into chat): ' OPENAI_API_KEY
  printf '\n'
fi
if [[ -z "${OPENAI_API_KEY:-}" ]]; then
  printf 'No API key entered. Nothing was sent.\n' >&2
  exit 1
fi
export OPENAI_API_KEY
read -r -p 'Exact model snapshot available to your API account: ' LAB_MODEL_SNAPSHOT
if [[ -z "$LAB_MODEL_SNAPSHOT" ]]; then
  printf 'No model snapshot entered. Nothing was sent.\n' >&2
  exit 1
fi
python3 live_evaluate.py --model "$LAB_MODEL_SNAPSHOT" --temperature 0 --repetitions 5 "$@"
