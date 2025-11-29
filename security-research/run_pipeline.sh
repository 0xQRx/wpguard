#!/bin/bash

# =============================================================================
# WordPressGuard Security Research Pipeline
# For Wordfence Bug Bounty Program
# =============================================================================

set -e

# Configuration
RESEARCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$RESEARCH_DIR/config"
TARGETS_DIR="$RESEARCH_DIR/targets"
REPORTS_DIR="$RESEARCH_DIR/reports"
AGENTS_DIR="$RESEARCH_DIR/agents"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_banner() {
    echo -e "${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║         WordPressGuard Security Research Pipeline             ║"
    echo "║              Wordfence Bug Bounty Edition                     ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_help() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  search <query>           Search for plugins matching query"
    echo "  download <slug>          Download a plugin for analysis"
    echo "  analyze <slug>           Run security analysis on downloaded plugin"
    echo "  validate <slug>          Validate a vulnerability report"
    echo "  pipeline <slug>          Run full pipeline (download → analyze → validate)"
    echo "  status                   Show current research status"
    echo "  clean                    Clean up temporary files"
    echo ""
    echo "Options:"
    echo "  --min-installs <n>       Minimum active installations (default: 50000)"
    echo "  --tier <tier>            Vulnerability tier: high_threat, common, standard"
    echo "  --help                   Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 search \"file upload\" --min-installs 25"
    echo "  $0 download contact-form-7"
    echo "  $0 analyze contact-form-7"
    echo "  $0 pipeline my-plugin --tier high_threat"
}

# Check dependencies
check_dependencies() {
    local missing=()

    if ! command -v wpguard &> /dev/null; then
        missing+=("wpguard")
    fi

    if ! command -v claude &> /dev/null; then
        missing+=("claude")
    fi

    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing[*]}"
        echo "Please install missing tools before running the pipeline."
        exit 1
    fi
}

# Ensure directories exist
ensure_directories() {
    mkdir -p "$TARGETS_DIR"
    mkdir -p "$REPORTS_DIR"
}

# Search for plugins
cmd_search() {
    local query="$1"
    local min_installs="${2:-50000}"

    if [ -z "$query" ]; then
        log_error "Search query required"
        echo "Usage: $0 search <query> [--min-installs <n>]"
        exit 1
    fi

    log_info "Searching for plugins: '$query' (min installs: $min_installs)"
    wpguard search "$query" --per-page 20

    echo ""
    log_info "To download a plugin: $0 download <slug>"
}

# Download a plugin
cmd_download() {
    local slug="$1"

    if [ -z "$slug" ]; then
        log_error "Plugin slug required"
        echo "Usage: $0 download <slug>"
        exit 1
    fi

    log_info "Downloading plugin: $slug"

    # Check if already downloaded
    if [ -d "$TARGETS_DIR/$slug" ]; then
        log_warn "Plugin already downloaded at $TARGETS_DIR/$slug"
        read -p "Re-download? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 0
        fi
        rm -rf "$TARGETS_DIR/$slug"
    fi

    # Download with wpguard
    wpguard download "$slug" --svn --extract --output-dir "$TARGETS_DIR"

    if [ -d "$TARGETS_DIR/$slug" ]; then
        log_success "Plugin downloaded to $TARGETS_DIR/$slug"

        # Create scope.yaml placeholder
        mkdir -p "$TARGETS_DIR/$slug"

        log_info "Next step: $0 analyze $slug"
    else
        log_error "Download failed"
        exit 1
    fi
}

# Run security analysis
cmd_analyze() {
    local slug="$1"
    local tier="${2:-standard}"

    if [ -z "$slug" ]; then
        log_error "Plugin slug required"
        echo "Usage: $0 analyze <slug> [--tier <tier>]"
        exit 1
    fi

    local target_dir="$TARGETS_DIR/$slug"

    if [ ! -d "$target_dir" ]; then
        log_error "Plugin not found: $target_dir"
        echo "Run '$0 download $slug' first"
        exit 1
    fi

    log_info "Running security analysis on: $slug"
    log_info "Tier: $tier"

    # Create reports directory
    mkdir -p "$REPORTS_DIR/$slug/poc"
    mkdir -p "$REPORTS_DIR/$slug/validation/evidence"

    # Run target researcher to generate scope
    log_info "[Stage 1/3] Running Target Researcher..."
    cd "$AGENTS_DIR/target-researcher"

    claude "Analyze the WordPress plugin at $target_dir and generate a scope.yaml file. \
            Focus on entry points, dangerous sinks, and data flows. \
            The scope should be tailored for Wordfence Bug Bounty with tier: $tier. \
            Save scope.yaml to $target_dir/scope.yaml"

    if [ ! -f "$target_dir/scope.yaml" ]; then
        log_warn "scope.yaml not generated, creating minimal scope"
        cat > "$target_dir/scope.yaml" << EOF
target:
  slug: "$slug"
  source_path: "$target_dir/"
scope:
  applicable_tiers:
    - $tier
output:
  report_path: "$REPORTS_DIR/$slug/"
EOF
    fi

    # Run security researcher
    log_info "[Stage 2/3] Running Security Researcher..."
    cd "$AGENTS_DIR/security-researcher"

    claude "Perform security analysis on the WordPress plugin at $target_dir \
            using the scope defined in $target_dir/scope.yaml. \
            Look for vulnerabilities in scope for Wordfence Bug Bounty. \
            Focus on: SQL injection, XSS, authentication bypass, file upload vulnerabilities. \
            Create vulnerability reports in $REPORTS_DIR/$slug/ \
            Create PoC scripts in $REPORTS_DIR/$slug/poc/"

    log_success "Analysis complete. Reports saved to $REPORTS_DIR/$slug/"
    log_info "Next step: $0 validate $slug"
}

# Validate a report
cmd_validate() {
    local slug="$1"

    if [ -z "$slug" ]; then
        log_error "Plugin slug required"
        echo "Usage: $0 validate <slug>"
        exit 1
    fi

    local report_dir="$REPORTS_DIR/$slug"

    if [ ! -d "$report_dir" ]; then
        log_error "No reports found for: $slug"
        echo "Run '$0 analyze $slug' first"
        exit 1
    fi

    log_info "Running QA/Triage validation on: $slug"

    # Run QA triager
    cd "$AGENTS_DIR/qa-triager"

    claude "Validate the vulnerability reports at $report_dir. \
            Check bounty eligibility against Wordfence program rules. \
            Verify CVSS scores and authentication requirements. \
            Create validation report at $report_dir/validation/validation_report.md"

    if [ -f "$report_dir/validation/validation_report.md" ]; then
        log_success "Validation complete!"
        echo ""
        echo "=== Validation Summary ==="
        head -50 "$report_dir/validation/validation_report.md"
    else
        log_warn "No validation report generated"
    fi
}

# Run full pipeline
cmd_pipeline() {
    local slug="$1"
    local tier="${2:-standard}"

    if [ -z "$slug" ]; then
        log_error "Plugin slug required"
        echo "Usage: $0 pipeline <slug> [--tier <tier>]"
        exit 1
    fi

    print_banner

    log_info "Starting full pipeline for: $slug"
    echo ""

    # Stage 1: Download
    echo -e "${YELLOW}═══ Stage 1: Download ═══${NC}"
    cmd_download "$slug"
    echo ""

    # Stage 2: Analyze
    echo -e "${YELLOW}═══ Stage 2: Security Analysis ═══${NC}"
    cmd_analyze "$slug" "$tier"
    echo ""

    # Stage 3: Validate
    echo -e "${YELLOW}═══ Stage 3: QA Validation ═══${NC}"
    cmd_validate "$slug"
    echo ""

    log_success "Pipeline complete for: $slug"
    echo ""
    echo "Results:"
    echo "  - Target: $TARGETS_DIR/$slug/"
    echo "  - Reports: $REPORTS_DIR/$slug/"
    echo "  - Validation: $REPORTS_DIR/$slug/validation/"
}

# Show status
cmd_status() {
    print_banner

    echo "=== Research Status ==="
    echo ""

    echo "Targets downloaded:"
    if [ -d "$TARGETS_DIR" ] && [ "$(ls -A $TARGETS_DIR 2>/dev/null)" ]; then
        for dir in "$TARGETS_DIR"/*/; do
            if [ -d "$dir" ]; then
                local slug=$(basename "$dir")
                local has_scope="No"
                [ -f "$dir/scope.yaml" ] && has_scope="Yes"
                echo "  - $slug (scope.yaml: $has_scope)"
            fi
        done
    else
        echo "  (none)"
    fi

    echo ""
    echo "Reports generated:"
    if [ -d "$REPORTS_DIR" ] && [ "$(ls -A $REPORTS_DIR 2>/dev/null)" ]; then
        for dir in "$REPORTS_DIR"/*/; do
            if [ -d "$dir" ]; then
                local slug=$(basename "$dir")
                local vuln_count=$(find "$dir" -name "vulnerability_report.md" 2>/dev/null | wc -l)
                local validated="No"
                [ -f "$dir/validation/validation_report.md" ] && validated="Yes"
                echo "  - $slug (reports: $vuln_count, validated: $validated)"
            fi
        done
    else
        echo "  (none)"
    fi
}

# Clean up
cmd_clean() {
    log_warn "This will remove all temporary files."
    read -p "Continue? [y/N] " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Cleaning up..."
        # Only clean specific temp files, not research data
        find "$TARGETS_DIR" -name "*.tmp" -delete 2>/dev/null || true
        find "$REPORTS_DIR" -name "*.tmp" -delete 2>/dev/null || true
        log_success "Cleanup complete"
    fi
}

# Main entry point
main() {
    local command="$1"
    shift || true

    # Parse global options
    local min_installs="50000"
    local tier="standard"
    local positional=()

    while [[ $# -gt 0 ]]; do
        case $1 in
            --min-installs)
                min_installs="$2"
                shift 2
                ;;
            --tier)
                tier="$2"
                shift 2
                ;;
            --help)
                print_help
                exit 0
                ;;
            *)
                positional+=("$1")
                shift
                ;;
        esac
    done

    # Restore positional parameters
    set -- "${positional[@]}"

    case $command in
        search)
            check_dependencies
            ensure_directories
            cmd_search "$1" "$min_installs"
            ;;
        download)
            check_dependencies
            ensure_directories
            cmd_download "$1"
            ;;
        analyze)
            check_dependencies
            ensure_directories
            cmd_analyze "$1" "$tier"
            ;;
        validate)
            check_dependencies
            ensure_directories
            cmd_validate "$1"
            ;;
        pipeline)
            check_dependencies
            ensure_directories
            cmd_pipeline "$1" "$tier"
            ;;
        status)
            cmd_status
            ;;
        clean)
            cmd_clean
            ;;
        --help|-h|help|"")
            print_help
            ;;
        *)
            log_error "Unknown command: $command"
            print_help
            exit 1
            ;;
    esac
}

main "$@"
