use ito::{
    App, accounts, config, db::Db, dns, http, kernel::LocalKernelDriver, logging, reconcile,
};
use std::{path::PathBuf, process::ExitCode};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Once logging runs, log the error so the journal records it at error priority; before
            // that, print it.
            if tracing::dispatcher::has_been_set() {
                tracing::error!(error = %e, "stopped");
            } else {
                eprintln!("ito: {e}");
            }
            ExitCode::FAILURE
        }
    }
}

#[derive(clap::Parser)]
#[command(version, about)]
struct Args {
    /// TOML configuration file
    #[arg(
        long = "config",
        value_name = "PATH",
        env = "ITO_CONFIG",
        default_value = "/etc/ito/config.toml"
    )]
    config_path: PathBuf,
    /// Validate the configuration and exit without starting
    #[arg(long)]
    check_config: bool,
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Parse the arguments, load the configuration and start logging.
    let args = <Args as clap::Parser>::parse();
    let config = config::load(&args.config_path)?;
    if args.check_config {
        println!("configuration valid");
        return Ok(());
    }
    logging::init(&config.log);

    // Open the database, which locks it, and the kernel interface.
    set_private_umask();
    let db = Db::connect(&config.database).await?;
    let kernel = LocalKernelDriver::new().await?;

    // Bind the listeners, build the app state and start the background tasks.
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let metrics_listener = match config.metrics_listen {
        Some(address) => Some(tokio::net::TcpListener::bind(address).await?),
        None => None,
    };
    let app = App::new(config, db, std::sync::Arc::new(kernel))?;
    if app.config.dns.is_some() {
        let address = dns::serve(app.clone()).await?;
        tracing::info!(%address, "DNS listening");
    }
    tokio::spawn(reconcile::run(app.clone()));
    if let Some(scim) = app.config.scim.clone() {
        tokio::spawn(accounts::sweep(app.clone(), scim));
    }
    if let Some(metrics_listener) = metrics_listener {
        let router = http::metrics::build_router(app.clone());
        tokio::spawn(async move {
            if let Err(e) = axum::serve(metrics_listener, router).await {
                tracing::error!(error = %e, "metrics listener stopped");
            }
        });
    }

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        address = %app.config.listen,
        "HTTP listening"
    );
    // Serve until a shutdown signal. The background tasks stop with the process, and WireGuard
    // state stays in the kernel.
    axum::serve(listener, http::build_router(app))
        .with_graceful_shutdown(wait_for_shutdown())
        .await?;
    Ok(())
}

#[expect(unsafe_code, reason = "umask has no safe std wrapper")]
fn set_private_umask() {
    // Called before any file or socket exists, so the database stays owner-only.
    unsafe {
        libc::umask(0o077);
    }
}

async fn wait_for_shutdown() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("signal handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}
