[private]
default:
    @just --list

# Builds the web portal and release binaries for the controller and Linux agent.
[group('build')]
build: build-web
    cargo build --release --locked

# Builds the web portal into web/dist, which the controller embeds.
[group('build')]
build-web:
    cd web && pnpm install --frozen-lockfile && pnpm build

# Builds the documentation site into build/site.
[group('build')]
build-docs:
    npx --yes antora@3.2.1 antora-playbook.yml

# Checks Rust formatting and lints the controller, Linux agent, and shared crates.
[group('check')]
check:
    cargo fmt --all --check
    cargo clippy --locked --workspace --exclude ito-agent-windows --exclude ito-tray --all-targets -- -D warnings

# Builds only the controller in debug mode and validates a configuration file.
[group('check')]
check-config config="config.sample.toml":
    cargo run --locked -p ito -- --config {{ quote(config) }} --check-config

# Runs Rust unit and integration tests for the controller, Linux agent, and shared crates.
[group('test')]
test-rust:
    cargo test --locked --workspace --exclude ito-agent-windows --exclude ito-tray

# Runs the web portal's unit tests.
[group('test')]
test-web:
    cd web && pnpm install --frozen-lockfile && pnpm test

# Runs real WireGuard kernel tests in disposable user and network namespaces.
[group('test')]
test-kernel:
    cargo test --locked -p ito --no-run
    ITO_KERNEL_TEST=1 unshare --user --map-root-user --net cargo test --locked --offline -p ito -- --ignored real_kernel_
    cargo test --locked -p ito-agent --no-run
    ITO_KERNEL_TEST=1 unshare --user --map-root-user --net sh -c 'ip link set lo up && cargo test --locked --offline -p ito-agent -- --ignored real_kernel_ --test-threads=1'

# Runs browser and agent tests with Keycloak and real WireGuard in a network namespace.
[group('test')]
test-e2e: build-web
    #!/bin/sh
    set -eu
    cargo build --locked -p ito -p ito-agent
    just idp-up
    trap 'just idp-down' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    cd web
    pasta --config-net -q -t none -u none -T 8080 -U none -- pnpm exec playwright test

# Builds the controller Debian package into dist/.
[group('package')]
deb-server: build-web
    cargo build --release --locked -p ito
    cargo deb -p ito --no-build --output dist/

# Builds the Linux agent Debian package into dist/.
[group('package')]
deb-agent:
    cargo build --release --locked -p ito-agent
    cargo deb -p ito-agent --no-build --output dist/

# Regenerates the configuration schema, defaults, and reference documentation.
[group('generate')]
generate-config:
    UPDATE_CONFIG_DOCS=1 cargo test --locked -p ito --test config_docs

# Regenerates the published OpenAPI document from the code.
[group('generate')]
generate-openapi:
    UPDATE_OPENAPI=1 cargo test --locked -p ito --test openapi

# Regenerates THIRD_PARTY_NOTICES.md using cargo-about.
[group('generate')]
generate-notices:
    cargo about generate --fail about.hbs -o THIRD_PARTY_NOTICES.md

# Starts Keycloak and the demo on http://localhost:8000 with WireGuard on UDP 51820.
[group('local services')]
demo-up: build-web
    #!/bin/sh
    set -eu
    if [ -f build/demo/pid ]; then
        echo "Demo state already exists; run just demo-down before restarting." >&2
        exit 1
    fi
    cargo build --locked -p ito
    just idp-up
    trap 'just demo-down' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    mkdir -p build/demo
    nohup pasta --config-net -q --pid "$PWD/build/demo/pid" -t 8000 -u 51820 -T 8080 -U none \
        -- web/e2e/serve.sh build/demo > build/demo/log 2>&1 &
    timeout 30 sh -c 'until curl -sf http://localhost:8000/health/ready >/dev/null; do sleep 1; done'
    trap - EXIT INT TERM
    echo "Ito runs on http://localhost:8000; sign in as admin or alice, with the name as password."

# Stops the demo and Keycloak, then deletes demo state once shutdown succeeds.
[group('local services')]
demo-down:
    #!/bin/sh
    set -eu
    if [ -f build/demo/pid ]; then
        pid=$(cat build/demo/pid)
        pkill -P "$pid" || [ "$?" -eq 1 ]
        # pasta exits after the controller, and only then frees the forwarded ports.
        if ! timeout 10 sh -c 'while kill -0 "$1" 2>/dev/null; do sleep 0.2; done' sh "$pid"; then
            echo "Demo shutdown timed out; keeping build/demo for another cleanup attempt." >&2
            exit 1
        fi
    fi
    just idp-down
    rm -rf build/demo

# Starts Keycloak on 127.0.0.1:8080; users admin and alice have their name as password.
[group('local services')]
idp-up:
    #!/bin/sh
    set -eu
    container=$(podman run -d --rm --name ito-idp -p 127.0.0.1:8080:8080 \
        -v ./web/e2e/realm.json:/opt/keycloak/data/import/realm.json:ro,Z \
        quay.io/keycloak/keycloak:26.8.1 start-dev --import-realm)
    trap 'podman rm -f --ignore "$container" >/dev/null' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    timeout 300 sh -c 'until curl -sf http://127.0.0.1:8080/realms/ito >/dev/null; do sleep 1; done'
    trap - EXIT INT TERM

# Stops Keycloak; succeeds if it is already absent.
[group('local services')]
idp-down:
    podman rm -f --ignore ito-idp
