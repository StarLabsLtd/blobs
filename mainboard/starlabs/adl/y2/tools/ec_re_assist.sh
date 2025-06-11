#!/usr/bin/env bash
set -euo pipefail

BIN_PATH="${1:-ec.bin}"
REF_ROOT="${2:-/home/sean/Insync/sean@starlabs.systems/Google Drive - Shared drives/Development/Reference Code/ECs}"

if [[ ! -f "$BIN_PATH" ]]; then
  echo "binary not found: $BIN_PATH" >&2
  exit 1
fi

if ! command -v rz-asm >/dev/null 2>&1; then
  echo "rz-asm is required" >&2
  exit 1
fi

bin_dir="$(cd "$(dirname "$BIN_PATH")" && pwd)"
bin_file="$(basename "$BIN_PATH")"
analysis_dir="$bin_dir/analysis"
mkdir -p "$analysis_dir"

find_offset() {
  local pattern="$1"
  local result
  result="$(grep -aboF "$pattern" "$BIN_PATH" 2>/dev/null | head -n 1 || true)"
  if [[ -n "$result" ]]; then
    printf '%s\n' "$result"
  else
    printf 'not found:%s\n' "$pattern"
  fi
}

disasm_prefix() {
  local bytes="$1"
  local hex
  hex="$(xxd -p -l "$bytes" "$BIN_PATH" | tr -d '\n')"
  rz-asm -a 8051 -d "$hex"
}

chunk_report() {
  local donor="$1"
  local outfile="$2"
  perl -e '
    use strict;
    use warnings;
    my ($a_path, $b_path, $chunk, $out_path) = @ARGV;
    open my $fa, "<:raw", $a_path or die $!;
    open my $fb, "<:raw", $b_path or die $!;
    local $/;
    my $a = <$fa>;
    my $b = <$fb>;
    open my $out, ">", $out_path or die $!;
    print $out "offset_hex\toffset_dec\tpercent_identical\tdiffering_bytes\n";
    my $len = length($a) < length($b) ? length($a) : length($b);
    for (my $off = 0; $off < $len; $off += $chunk) {
      my $size = $chunk;
      $size = $len - $off if $off + $size > $len;
      my $diff = 0;
      for (my $i = 0; $i < $size; $i++) {
        $diff++ if substr($a, $off + $i, 1) ne substr($b, $off + $i, 1);
      }
      my $same = $size - $diff;
      my $pct = sprintf("%.2f", ($same / $size) * 100);
      printf $out "0x%05X\t%d\t%s\t%d\n", $off, $off, $pct, $diff;
    }
    close $out;
  ' "$BIN_PATH" "$donor" 4096 "$outfile"
}

similarity_report() {
  local outfile="$1"
  local tmp
  tmp="$(mktemp)"
  find "$REF_ROOT" -type f -name '*.bin' -size 131072c | while IFS= read -r ref; do
    diffcount="$((0))"
    diffcount="$( { cmp -l "$BIN_PATH" "$ref" 2>/dev/null || true; } | wc -l )"
    same=$((131072 - diffcount))
    pct="$(awk -v s="$same" 'BEGIN { printf "%.2f", (s / 131072) * 100 }')"
    printf '%s\t%s\t%s\n' "$pct" "$diffcount" "$ref"
  done | sort -rn > "$tmp"

  {
    echo -e "percent_identical\tdiffering_bytes\treference_bin"
    sed -n '1,20p' "$tmp"
  } > "$outfile"
  rm -f "$tmp"
}

{
  echo "# EC Reverse-Engineering Assist"
  echo
  echo "Binary: $bin_file"
  echo "Path: $BIN_PATH"
  echo
  echo "## Basic Metadata"
  file "$BIN_PATH"
  wc -c "$BIN_PATH"
  sha256sum "$BIN_PATH"
  echo
  echo "## Signature Offsets"
  find_offset 'ITE EC-V14.6   '
  find_offset 'INTEL ICL MRD.$'
  find_offset '2025/10/28'
  find_offset '13:43:02'
  find_offset 'EC-DNB19-1.09-BOSGAME-TEST'
  echo
  echo "## Prefix Hexdump"
  xxd -g 1 -l 96 "$BIN_PATH"
  echo
  echo "## Prefix Disassembly (first 64 bytes, 8051)"
  disasm_prefix 64
  echo
  echo "## Build Region Hexdump"
  xxd -g 1 -s 0x7f80 -l 96 "$BIN_PATH"
  echo
  echo "## Local ADL Sibling Similarity"
  for sibling in "$bin_dir/../hz/ec.bin" "$bin_dir/../i5/ec.bin"; do
    if [[ -f "$sibling" ]]; then
      diffcount="$((0))"
      diffcount="$( { cmp -l "$BIN_PATH" "$sibling" 2>/dev/null || true; } | wc -l )"
      same=$((131072 - diffcount))
      pct="$(awk -v s="$same" 'BEGIN { printf "%.2f", (s / 131072) * 100 }')"
      printf '%s\t%s\t%s\n' "$pct" "$diffcount" "$sibling"
    fi
  done | sort -rn
  echo
  echo "## Strings"
  strings -a -n 6 "$BIN_PATH" | sed -n '1,80p'
} > "$analysis_dir/${bin_file%.bin}.inspection.txt"

similarity_report "$analysis_dir/${bin_file%.bin}.reference-similarity.tsv"

best_donor=""
if IFS=$'\t' read -r _pct _diff best_donor < <(sed -n '2p' "$analysis_dir/${bin_file%.bin}.reference-similarity.tsv"); then
  if [[ -n "$best_donor" && -f "$best_donor" ]]; then
    chunk_report "$best_donor" "$analysis_dir/${bin_file%.bin}.best-donor-chunks.tsv"
  fi
fi

echo "wrote:"
echo "  $analysis_dir/${bin_file%.bin}.inspection.txt"
echo "  $analysis_dir/${bin_file%.bin}.reference-similarity.tsv"
if [[ -n "$best_donor" && -f "$best_donor" ]]; then
  echo "  $analysis_dir/${bin_file%.bin}.best-donor-chunks.tsv"
fi
