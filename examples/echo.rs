use std::io;
use std::net::SocketAddrV4;

use adln_networking::{Endpoint, Event, GameId, SendError, ServerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let address: SocketAddrV4 = args
        .next()
        .ok_or("Specify <IPv4:port> <game-id> <application-version>")?
        .parse()?;
    let game = GameId(args.next().ok_or("Missing game ID")?.parse()?);
    let version = args.next().ok_or("Missing application version")?.parse()?;
    if args.next().is_some() {
        return Err("Unexpected argument".into());
    }
    let mut endpoint = Endpoint::bind(ServerConfig::new(address, game, vec![version])).await?;
    println!("Anonymous ADLN echo listening on {}", endpoint.local_addr());
    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => { result?; break; }
            event = endpoint.next_event() => match event? {
                Some(Event::Message { connection, channel, payload, .. }) => {
                    match endpoint.send(connection, channel, &payload) {
                        Ok(()) | Err(SendError::RateLimited | SendError::Backpressure) => (),
                        Err(error) => return Err(io::Error::other(error).into()),
                    }
                }
                Some(Event::Connected(connection)) => println!("Connected: {:?}", connection.id),
                Some(Event::Disconnected { connection, reason }) => println!("Disconnected: {:?} ({reason:?})", connection.id),
                None => break,
            }
        }
    }
    endpoint.shutdown();
    Ok(())
}
