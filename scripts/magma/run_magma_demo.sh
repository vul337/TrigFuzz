#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)

BUG=PDF010
ENGINE=both
BUDGET=3600
OUT_ROOT=/root/magma-eval/trigfuzz-release-demo
SEEDS=
BUILD=1
WITH_BYTE_AWARE=0
FILTER_SEEDS=1
SEED_FILTER_TIMEOUT=${SEED_FILTER_TIMEOUT:-10}

usage() {
  cat <<'EOF'
Usage:
  scripts/magma/run_magma_demo.sh [options]

Runs a local Magma target with release TrigFuzz engines and matching baselines.

Default target:
  PDF010

Options:
  --bug BUG              Magma bug id, default: PDF010
  --engine ENGINE        both | aflgo | aflpp-selective, default: both
  --budget SECONDS       Per-variant fuzzing budget, default: 3600
  --out-root DIR         Output parent, default: /root/magma-eval/trigfuzz-release-demo
  --seeds DIR            Seed corpus. Default is inferred from local Magma paths.
  --no-seed-filter       Use the seed corpus directly, without startup replay filtering.
  --no-build             Do not build missing fuzzers/targets.
  --with-byte-aware      Enable the optional AFLGo triggering byte-aware stage.
  -h, --help             Show this help.

Environment overrides:
  AFLGO_FUZZER           default: engines/aflgo-trigfuzz/afl-2.57b/afl-fuzz
  AFLPP_RAW_FUZZER       default: engines/aflplusplus-selective/afl-fuzz
  AFLPP_SELECTIVE_FUZZER default: engines/aflplusplus-selective/afl-fuzz
  AFLGO_CUTOFF           default: 10m
  SEED_FILTER_TIMEOUT    Per-seed startup replay timeout, default: 10
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --bug)
      BUG=${2:?missing value for --bug}
      shift 2
      ;;
    --engine)
      ENGINE=${2:?missing value for --engine}
      shift 2
      ;;
    --budget)
      BUDGET=${2:?missing value for --budget}
      shift 2
      ;;
    --out-root)
      OUT_ROOT=${2:?missing value for --out-root}
      shift 2
      ;;
    --seeds)
      SEEDS=${2:?missing value for --seeds}
      shift 2
      ;;
    --no-seed-filter)
      FILTER_SEEDS=0
      shift
      ;;
    --no-build)
      BUILD=0
      shift
      ;;
    --with-byte-aware)
      WITH_BYTE_AWARE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$ENGINE" in
  both|aflgo|aflpp-selective) ;;
  *)
    echo "bad --engine: $ENGINE" >&2
    exit 2
    ;;
esac

META=/root/magma-eval/paper30_trigger_meta.py
if [ ! -f "$META" ]; then
  echo "missing local Magma metadata helper: $META" >&2
  exit 1
fi

meta_field() {
  python3 -B "$META" field "$BUG" "$1"
}

PROJECT=$(meta_field project)
PROGRAM=$(meta_field program)
ARGV_MODE=$(meta_field argv_mode)
A_FLAG=$(meta_field a_flag)
SEQ_NUM=${SEQ_NUM:-1}
AFLGO_CUTOFF=${AFLGO_CUTOFF:-10m}

case "$ARGV_MODE" in
  stdin|file) ;;
  *)
    echo "unsupported argv mode for $BUG: $ARGV_MODE" >&2
    exit 2
    ;;
esac

if [ -z "$SEEDS" ]; then
  if [ -d "/root/magma-eval/seeds-filtered-20260616-pdf/$BUG" ]; then
    SEEDS=/root/magma-eval/seeds-filtered-20260616-pdf/$BUG
  elif [ -d "/root/magma-eval/seeds/$BUG" ]; then
    SEEDS=/root/magma-eval/seeds/$BUG
  elif [ -d "/root/magma/targets/$PROJECT/corpus/$PROGRAM" ]; then
    SEEDS=/root/magma/targets/$PROJECT/corpus/$PROGRAM
  else
    echo "could not infer seed corpus for $BUG; pass --seeds DIR" >&2
    exit 1
  fi
fi

if [ ! -d "$SEEDS" ]; then
  echo "seed corpus does not exist: $SEEDS" >&2
  exit 1
fi

AFLGO_FUZZER=${AFLGO_FUZZER:-$REPO_ROOT/engines/aflgo-trigfuzz/afl-2.57b/afl-fuzz}
AFLPP_RAW_FUZZER=${AFLPP_RAW_FUZZER:-$REPO_ROOT/engines/aflplusplus-selective/afl-fuzz}
AFLPP_SELECTIVE_FUZZER=${AFLPP_SELECTIVE_FUZZER:-$REPO_ROOT/engines/aflplusplus-selective/afl-fuzz}

AFLGO_TARGET=/root/magma-work-paper30/$BUG/target-aflgo
AFLPP_TARGET=/root/magma-work-paper30-aflpp/$BUG/target-aflpp
AFLPP_SELECTIVE_TARGET=/root/magma-work-paper30-aflpp-selective/$BUG/target-aflpp-selective

log() {
  printf '[%s] %s\n' "$BUG" "$*"
}

ensure_fuzzers() {
  if [ "$BUILD" != 1 ]; then
    return
  fi
  if { [ "$ENGINE" = both ] || [ "$ENGINE" = aflgo ]; } && [ ! -x "$AFLGO_FUZZER" ]; then
    log "building AFLGo-based TrigFuzz fuzzer"
    make -C "$REPO_ROOT/engines/aflgo-trigfuzz/afl-2.57b" afl-fuzz afl-gcc
  fi
  if { [ "$ENGINE" = both ] || [ "$ENGINE" = aflpp-selective ]; } && { [ ! -x "$AFLPP_RAW_FUZZER" ] || [ ! -x "$AFLPP_SELECTIVE_FUZZER" ]; }; then
    log "building selective AFL++ TrigFuzz fuzzer"
    make -C "$REPO_ROOT/engines/aflplusplus-selective" source-only
  fi
}

ensure_target() {
  local path=$1
  local builder=$2
  if [ -x "$path" ]; then
    return
  fi
  if [ "$BUILD" != 1 ]; then
    echo "missing target and --no-build was set: $path" >&2
    exit 1
  fi
  if [ ! -x "$builder" ]; then
    echo "missing local build helper: $builder" >&2
    exit 1
  fi
  log "building target via $builder"
  "$builder" "$BUG"
  if [ ! -x "$path" ]; then
    echo "target build did not produce expected binary: $path" >&2
    exit 1
  fi
}

ensure_targets() {
  if [ "$ENGINE" = both ] || [ "$ENGINE" = aflgo ]; then
    ensure_target "$AFLGO_TARGET" /root/magma-eval/build_paper_target.sh
  fi
  if [ "$ENGINE" = both ] || [ "$ENGINE" = aflpp-selective ]; then
    ensure_target "$AFLPP_TARGET" /root/magma-eval/build_paper_target_aflpp_trig.sh
    ensure_target "$AFLPP_SELECTIVE_TARGET" /root/magma-eval/build_paper_target_aflpp_selective.sh
  fi
}

target_args() {
  local target=$1
  local run_dir=$2
  case "$BUG" in
    PDF003)
      mkdir -p "$run_dir/pdfimages-out"
      printf '%s\0%s\0%s\0' "$target" "@@" "$run_dir/pdfimages-out/out"
      ;;
    PDF010)
      mkdir -p "$run_dir/pdftoppm-out"
      printf '%s\0%s\0%s\0%s\0%s\0' "$target" -mono -cropbox "@@" "$run_dir/pdftoppm-out/out"
      ;;
    TIF009)
      mkdir -p "$run_dir/tif009-out"
      printf '%s\0%s\0%s\0%s\0' "$target.real" -M "@@" "$run_dir/tif009-out/out.tif"
      ;;
    *)
      if [ "$ARGV_MODE" = file ]; then
        printf '%s\0%s\0' "$target" "@@"
      else
        printf '%s\0' "$target"
      fi
      ;;
  esac
}

target_args_for_replay() {
  local target=$1
  local input=$2
  local run_dir=$3
  case "$BUG" in
    PDF003)
      mkdir -p "$run_dir/replay-pdfimages-out"
      printf '%s\0%s\0%s\0' "$target" "$input" "$run_dir/replay-pdfimages-out/out"
      ;;
    PDF010)
      mkdir -p "$run_dir/replay-pdftoppm-out"
      printf '%s\0%s\0%s\0%s\0%s\0' "$target" -mono -cropbox "$input" "$run_dir/replay-pdftoppm-out/out"
      ;;
    TIF009)
      mkdir -p "$run_dir/replay-tif009-out"
      printf '%s\0%s\0%s\0%s\0' "$target.real" -M "$input" "$run_dir/replay-tif009-out/out.tif"
      ;;
    *)
      if [ "$ARGV_MODE" = file ]; then
        printf '%s\0%s\0' "$target" "$input"
      else
        printf '%s\0' "$target"
      fi
      ;;
  esac
}

variant_target() {
  case "$1" in
    aflgo_raw|trigfuzz_aflgo) printf '%s\n' "$AFLGO_TARGET" ;;
    aflpp_raw) printf '%s\n' "$AFLPP_TARGET" ;;
    trigfuzz_aflpp_selective) printf '%s\n' "$AFLPP_SELECTIVE_TARGET" ;;
    *) return 1 ;;
  esac
}

variant_fuzzer() {
  case "$1" in
    aflgo_raw|trigfuzz_aflgo) printf '%s\n' "$AFLGO_FUZZER" ;;
    aflpp_raw) printf '%s\n' "$AFLPP_RAW_FUZZER" ;;
    trigfuzz_aflpp_selective) printf '%s\n' "$AFLPP_SELECTIVE_FUZZER" ;;
    *) return 1 ;;
  esac
}

seed_filter_target() {
  if [ "$ENGINE" = both ] || [ "$ENGINE" = aflgo ]; then
    printf '%s\n' "$AFLGO_TARGET"
  else
    printf '%s\n' "$AFLPP_SELECTIVE_TARGET"
  fi
}

prepare_seed_corpus() {
  if [ "$FILTER_SEEDS" != 1 ]; then
    printf 'raw_seeds=%s\nseed_filter=disabled\nseeds=%s\n' "$SEEDS" "$SEEDS" > "$RUN_ROOT/seed-filter.meta"
    return
  fi

  local raw_seeds=$SEEDS
  local target filtered_dir log_file kept=0 skipped=0 total=0
  target=$(seed_filter_target)
  filtered_dir=$RUN_ROOT/seeds-filtered
  log_file=$RUN_ROOT/seed-filter.log
  mkdir -p "$filtered_dir"
  : > "$log_file"

  log "filtering startup seeds with $target"
  local seed name replay_dir stdout_file stderr_file status
  while IFS= read -r seed; do
    [ -f "$seed" ] || continue
    total=$((total + 1))
    name=$(basename -- "$seed")
    replay_dir=$RUN_ROOT/seed-filter-replay/$total
    stdout_file=$replay_dir/stdout.txt
    stderr_file=$replay_dir/stderr.txt
    mkdir -p "$replay_dir"

    local -a replay_args=()
    while IFS= read -r -d '' arg; do
      replay_args+=("$arg")
    done < <(target_args_for_replay "$target" "$seed" "$replay_dir")

    set +e
    if [ "$ARGV_MODE" = stdin ]; then
      timeout "$SEED_FILTER_TIMEOUT" "${replay_args[@]}" < "$seed" > "$stdout_file" 2> "$stderr_file"
    else
      timeout "$SEED_FILTER_TIMEOUT" "${replay_args[@]}" > "$stdout_file" 2> "$stderr_file"
    fi
    status=$?
    set -e

    if [ "$status" -eq 0 ]; then
      cp -a "$seed" "$filtered_dir/$name"
      kept=$((kept + 1))
    else
      printf 'skip\t%s\tstatus=%s\n' "$name" "$status" >> "$log_file"
      skipped=$((skipped + 1))
    fi
  done < <(find -L "$raw_seeds" -maxdepth 1 -type f | sort)

  if [ "$kept" -eq 0 ]; then
    echo "seed filtering kept no inputs from $raw_seeds" >&2
    exit 1
  fi

  SEEDS=$filtered_dir
  {
    printf 'raw_seeds=%s\n' "$raw_seeds"
    printf 'seed_filter=enabled\n'
    printf 'seed_filter_target=%s\n' "$target"
    printf 'seed_filter_timeout=%s\n' "$SEED_FILTER_TIMEOUT"
    printf 'seed_filter_total=%s\n' "$total"
    printf 'seed_filter_kept=%s\n' "$kept"
    printf 'seed_filter_skipped=%s\n' "$skipped"
    printf 'seeds=%s\n' "$SEEDS"
  } > "$RUN_ROOT/seed-filter.meta"
  log "seed filter kept $kept/$total inputs"
}

run_variant() {
  local variant=$1
  local run_dir=$2
  local fuzzer target out cmd_log run_log exit_log
  fuzzer=$(variant_fuzzer "$variant")
  target=$(variant_target "$variant")
  out=$run_dir/out
  cmd_log=$run_dir/command.txt
  run_log=$run_dir/fuzzer.log
  exit_log=$run_dir/exit.meta
  mkdir -p "$run_dir"

  local -a envs=()
  local -a args=(-i "$SEEDS" -o "$out" -m none -t 5000 -d)
  case "$variant" in
    aflgo_raw)
      args+=(-z exp -c "$AFLGO_CUTOFF")
      ;;
    trigfuzz_aflgo)
      args+=(-z exp -c "$AFLGO_CUTOFF" -a "$A_FLAG" -s "$SEQ_NUM")
      if [ "$WITH_BYTE_AWARE" = 1 ]; then
        envs+=(AFL_TRIG_ENABLE_BYTE_AWARE_MUTATION=1)
      fi
      ;;
    aflpp_raw)
      ;;
    trigfuzz_aflpp_selective)
      envs+=(AFL_TRIGFUZZ_ENABLE=1 AFL_TRIGFUZZ_INS_NUM="$A_FLAG" AFL_TRIGFUZZ_SEQ_NUM="$SEQ_NUM")
      ;;
  esac

  local -a targ=()
  while IFS= read -r -d '' item; do
    targ+=("$item")
  done < <(target_args "$target" "$run_dir")

  {
    printf 'bug=%s\nproject=%s\nprogram=%s\nvariant=%s\nbudget=%s\nseeds=%s\ntarget=%s\nargv_mode=%s\na_flag=%s\nseq_num=%s\n' \
      "$BUG" "$PROJECT" "$PROGRAM" "$variant" "$BUDGET" "$SEEDS" "$target" "$ARGV_MODE" "$A_FLAG" "$SEQ_NUM"
    printf 'command='
    printf '%q ' env "${envs[@]}" timeout "$BUDGET" "$fuzzer" "${args[@]}" -- "${targ[@]}"
    printf '\n'
  } > "$cmd_log"

  log "launching $variant for ${BUDGET}s"
  (
    set +e
    start_epoch=$(date +%s)
    ulimit -c 0
    export AFL_NO_UI=1
    export AFL_SKIP_CPUFREQ=1
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export AFL_NO_AFFINITY=1
    env "${envs[@]}" timeout "$BUDGET" "$fuzzer" "${args[@]}" -- "${targ[@]}" > "$run_log" 2>&1
    raw_status=$?
    end_epoch=$(date +%s)
    normalized_status=$raw_status
    if [ "$raw_status" -eq 124 ]; then
      normalized_status=0
    fi
    {
      printf 'variant=%s\npid=%s\nstart_epoch=%s\nend_epoch=%s\nraw_status=%s\nnormalized_status=%s\n' \
        "$variant" "$BASHPID" "$start_epoch" "$end_epoch" "$raw_status" "$normalized_status"
    } > "$exit_log"
    exit "$normalized_status"
  ) &
  printf '%s\t%s\n' "$variant" "$!" >> "$RUN_ROOT/pids.tsv"
}

crash_dir_for() {
  local out=$1
  if [ -d "$out/crashes" ]; then
    printf '%s\n' "$out/crashes"
  elif [ -d "$out/default/crashes" ]; then
    printf '%s\n' "$out/default/crashes"
  else
    return 1
  fi
}

crash_time_ms() {
  local name
  name=$(basename -- "$1")
  if [[ "$name" =~ time:([0-9]+) ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
  elif [[ "$name" =~ id:[0-9]+,([0-9]+),sig: ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
  else
    printf '0\n'
  fi
}

triage_variant() {
  local variant=$1
  local run_dir=$2
  local target out crash_dir
  target=$(variant_target "$variant")
  out=$run_dir/out
  local crash_count=0 checked=0 confirmed=0 first_ms= first_file= marker=

  if crash_dir=$(crash_dir_for "$out" 2>/dev/null); then
    local item
    while IFS= read -r item; do
      [ -f "$item" ] || continue
      case "$(basename -- "$item")" in README*|README.txt) continue ;; esac
      crash_count=$((crash_count + 1))
    done < <(find "$crash_dir" -maxdepth 1 -type f | sort)

    while IFS= read -r item; do
      [ -f "$item" ] || continue
      case "$(basename -- "$item")" in README*|README.txt) continue ;; esac
      checked=$((checked + 1))
      local replay_dir stderr_file stdout_file
      replay_dir=$run_dir/replay-$checked
      mkdir -p "$replay_dir"
      stderr_file=$replay_dir/stderr.txt
      stdout_file=$replay_dir/stdout.txt
      local -a replay_args=()
      while IFS= read -r -d '' arg; do
        replay_args+=("$arg")
      done < <(target_args_for_replay "$target" "$item" "$replay_dir")
      set +e
      if [ "$ARGV_MODE" = stdin ]; then
        timeout 10 "${replay_args[@]}" < "$item" > "$stdout_file" 2> "$stderr_file"
      else
        timeout 10 "${replay_args[@]}" > "$stdout_file" 2> "$stderr_file"
      fi
      set -e
      if grep -q "MAGMA_BUG" "$stderr_file" "$stdout_file"; then
        confirmed=1
        first_ms=$(crash_time_ms "$item")
        first_file=$item
        marker=$(grep -h "MAGMA_BUG" "$stderr_file" "$stdout_file" | head -1)
        break
      fi
    done < <(find "$crash_dir" -maxdepth 1 -type f | sort)
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$variant" "$crash_count" "$checked" "$confirmed" "${first_ms:-}" "${first_file:-}" "${marker:-}" "$run_dir" \
    >> "$RUN_ROOT/summary.tsv"
}

ensure_fuzzers
ensure_targets

timestamp=$(date +%Y%m%d-%H%M%S)
RUN_ROOT=$OUT_ROOT/${BUG}-${ENGINE}-${timestamp}
mkdir -p "$RUN_ROOT"
RAW_SEEDS=$SEEDS
prepare_seed_corpus
printf 'bug=%s\nproject=%s\nprogram=%s\nengine=%s\nbudget=%s\nraw_seeds=%s\nseeds=%s\na_flag=%s\nseq_num=%s\naflgo_cutoff=%s\nwith_byte_aware=%s\nseed_filter=%s\nseed_filter_timeout=%s\n' \
  "$BUG" "$PROJECT" "$PROGRAM" "$ENGINE" "$BUDGET" "$RAW_SEEDS" "$SEEDS" "$A_FLAG" "$SEQ_NUM" "$AFLGO_CUTOFF" "$WITH_BYTE_AWARE" "$FILTER_SEEDS" "$SEED_FILTER_TIMEOUT" \
  > "$RUN_ROOT/run.meta"
: > "$RUN_ROOT/pids.tsv"

variants=()
case "$ENGINE" in
  both)
    variants=(aflgo_raw trigfuzz_aflgo aflpp_raw trigfuzz_aflpp_selective)
    ;;
  aflgo)
    variants=(aflgo_raw trigfuzz_aflgo)
    ;;
  aflpp-selective)
    variants=(aflpp_raw trigfuzz_aflpp_selective)
    ;;
esac

for variant in "${variants[@]}"; do
  run_variant "$variant" "$RUN_ROOT/$variant"
done

fail=0
while IFS=$'\t' read -r variant pid; do
  [ -n "$variant" ] || continue
  if ! wait "$pid"; then
    fail=1
  fi
done < "$RUN_ROOT/pids.tsv"

printf 'variant\tcrash_count\tchecked\tconfirmed\tfirst_ms\tfirst_file\tmarker\trun_dir\n' > "$RUN_ROOT/summary.tsv"
for variant in "${variants[@]}"; do
  triage_variant "$variant" "$RUN_ROOT/$variant"
done

log "run root: $RUN_ROOT"
if command -v column >/dev/null 2>&1; then
  column -t -s $'\t' "$RUN_ROOT/summary.tsv"
else
  cat "$RUN_ROOT/summary.tsv"
fi
exit "$fail"
