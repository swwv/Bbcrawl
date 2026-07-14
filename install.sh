#!/usr/bin/env bash
#
#  install.sh — set up every dependency bbcrawl.sh can use.
#  Idempotent: safe to re-run. Skips whatever is already installed.
#  Supports Linux (apt/dnf/pacman) and macOS (brew). Nothing fails the whole
#  run — each tool installs best-effort and the summary lists what's missing.
#
set -uo pipefail
G=$'\e[92m'; Y=$'\e[93m'; B=$'\e[94m'; BOLD=$'\e[1m'; END=$'\e[0m'
ok(){ echo -e "${G}[+]${END} $*"; }
inf(){ echo -e "${B}[*]${END} $*"; }
wrn(){ echo -e "${Y}[!]${END} $*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

echo -e "${BOLD}bbcrawl dependency installer${END}\n"

# ── package manager / OS ───────────────────────────────────────────────────
OS="$(uname -s)"
PM=""
if [[ "$OS" == "Darwin" ]]; then PM="brew"
elif have apt-get; then PM="apt"
elif have dnf; then PM="dnf"
elif have pacman; then PM="pacman"
fi
inf "os=$OS  package-manager=${PM:-none}"

pm_install() { # pm_install pkg...
  case "$PM" in
    brew)   brew install "$@" 2>/dev/null ;;
    apt)    sudo apt-get install -y "$@" 2>/dev/null ;;
    dnf)    sudo dnf install -y "$@" 2>/dev/null ;;
    pacman) sudo pacman -S --noconfirm "$@" 2>/dev/null ;;
    *) wrn "no package manager; install $* manually" ;;
  esac
}

# ── base packages: git, curl, python3, pip, jq ─────────────────────────────
inf "ensuring base packages (git curl python3 pip jq)"
for base in git curl jq; do have "$base" || pm_install "$base"; done
have python3 || pm_install python3
have pip3 || pm_install python3-pip
have pipx || pm_install pipx || python3 -m pip install --user -q pipx 2>/dev/null || true

# ── Go toolchain ───────────────────────────────────────────────────────────
if ! have go; then
  inf "installing Go"
  if [[ "$PM" == "brew" ]]; then brew install go 2>/dev/null
  else
    GOVER="1.22.5"; ARCH="$(uname -m)"
    case "$ARCH" in x86_64) GARCH=amd64;; aarch64|arm64) GARCH=arm64;; *) GARCH=amd64;; esac
    curl -sSL "https://go.dev/dl/go${GOVER}.linux-${GARCH}.tar.gz" -o /tmp/go.tgz 2>/dev/null && \
      sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz 2>/dev/null
    export PATH="$PATH:/usr/local/go/bin"
  fi
fi
if have go; then
  export GOPATH="${GOPATH:-$HOME/go}"
  export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"
  ok "go: $(go version 2>/dev/null | awk '{print $3}')"
  # make the go bin dir permanent in the shell rc
  RC="$HOME/.bashrc"; [[ "$SHELL" == *zsh* ]] && RC="$HOME/.zshrc"
  grep -q 'go/bin' "$RC" 2>/dev/null || echo 'export PATH="$PATH:$HOME/go/bin:/usr/local/go/bin"' >> "$RC"
else
  wrn "Go not available — Go-based tools will be skipped"
fi

# ── Go tools ───────────────────────────────────────────────────────────────
declare -A GOTOOLS=(
  [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
  [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
  [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  [dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  [gau]="github.com/lc/gau/v2/cmd/gau@latest"
  [waybackurls]="github.com/tomnomnom/waybackurls@latest"
  [assetfinder]="github.com/tomnomnom/assetfinder@latest"
  [gf]="github.com/tomnomnom/gf@latest"
  [qsreplace]="github.com/tomnomnom/qsreplace@latest"
  [anew]="github.com/tomnomnom/anew@latest"
  [unfurl]="github.com/tomnomnom/unfurl@latest"
  [hakrawler]="github.com/hakluke/hakrawler@latest"
  [gospider]="github.com/jaeles-project/gospider@latest"
  [jsluice]="github.com/BishopFox/jsluice/cmd/jsluice@latest"
  [subzy]="github.com/PentestPad/subzy@latest"
  [gowitness]="github.com/sensepost/gowitness@latest"
)
if have go; then
  inf "installing Go tools (this can take a few minutes)…"
  for name in "${!GOTOOLS[@]}"; do
    if have "$name"; then ok "$name already present"; continue; fi
    inf "go install $name"
    GOFLAGS=-buildvcs=false go install "${GOTOOLS[$name]}" 2>/dev/null \
      && ok "installed $name" || wrn "failed: $name (install manually if needed)"
  done
fi

# ── Python tools: uro, paramspider, arjun ──────────────────────────────────
pyinstall() { # pyinstall pkg [gitspec]
  local name="$1" spec="${2:-$1}"
  have "$name" && { ok "$name already present"; return; }
  inf "installing $name"
  if have pipx; then pipx install "$spec" 2>/dev/null && { ok "installed $name"; return; }; fi
  pip3 install --user -q "$spec" 2>/dev/null && ok "installed $name" \
    || pip3 install --user -q --break-system-packages "$spec" 2>/dev/null && ok "installed $name" \
    || wrn "failed: $name"
}
pyinstall uro
pyinstall paramspider "git+https://github.com/devanshbatham/paramspider"
pyinstall arjun

# ── trufflehog ─────────────────────────────────────────────────────────────
if ! have trufflehog; then
  inf "installing trufflehog"
  if [[ "$PM" == "brew" ]]; then brew install trufflehog 2>/dev/null
  else curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sudo sh -s -- -b /usr/local/bin 2>/dev/null; fi
  have trufflehog && ok "installed trufflehog" || wrn "trufflehog install failed"
else ok "trufflehog already present"; fi

# ── gf patterns (~/.gf) ────────────────────────────────────────────────────
inf "installing gf patterns into ~/.gf"
mkdir -p "$HOME/.gf"
tmpd="$(mktemp -d)"
# tomnomnom's canonical patterns
git clone -q --depth 1 https://github.com/tomnomnom/gf "$tmpd/gf" 2>/dev/null \
  && cp "$tmpd"/gf/examples/*.json "$HOME/.gf/" 2>/dev/null
# 1ndianl33t's larger pattern pack (xss, ssrf, ssti, lfi, rce, idor, ...)
git clone -q --depth 1 https://github.com/1ndianl33t/Gf-Patterns "$tmpd/extra" 2>/dev/null \
  && cp "$tmpd"/extra/*.json "$HOME/.gf/" 2>/dev/null
rm -rf "$tmpd"
gfc=$(ls "$HOME/.gf/"*.json 2>/dev/null | wc -l | tr -d ' ')
ok "gf patterns available: $gfc"

# ── nuclei templates ───────────────────────────────────────────────────────
if have nuclei; then inf "updating nuclei templates"; nuclei -update-templates -silent 2>/dev/null || true; fi

# ── verify ─────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}verification${END}"
ALL=(subfinder httpx katana nuclei dnsx gau waybackurls assetfinder gf qsreplace anew unfurl uro hakrawler gospider jsluice subzy gowitness paramspider arjun trufflehog)
present=(); missing=()
for t in "${ALL[@]}"; do have "$t" && present+=("$t") || missing+=("$t"); done
echo -e "${G}present (${#present[@]}):${END} ${present[*]}"
[[ ${#missing[@]} -gt 0 ]] && echo -e "${Y}missing (${#missing[@]}):${END} ${missing[*]}"
echo
ok "done. Open a new shell (or 'source ~/.bashrc') so PATH picks up \$HOME/go/bin."
echo -e "then run: ${BOLD}./bbcrawl.sh -d target.com --all${END}"
