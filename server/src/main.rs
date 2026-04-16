#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    io3233_server::run().await
}
