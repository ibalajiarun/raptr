#[tokio::main]
async fn main() {
    #[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
    raikou::simulation_test::main().await;
}
