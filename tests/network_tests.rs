use std::error::Error;
use libp2p::{
    core::{Multiaddr, upgrade, transport::memory::MemoryTransport}, 
    identity, 
    mplex, 
    noise::{Keypair as NoiseKeypair, NoiseConfig, X25519Spec}, 
    swarm::{SwarmBuilder,SwarmEvent}, 
    PeerId, 
    Transport, 
    ping::{self, PingConfig}, 
    futures::StreamExt
};



#[tokio::test]
async fn test_two_nodes_connect_and_ping() -> Result<(), Box<dyn Error>> {
    let id_keys1 = identity::Keypair::generate_ed25519();
    let id_keys2 = identity::Keypair::generate_ed25519();

    let noise_keys1 = NoiseKeypair::<X25519Spec>::new().into_authentic(&id_keys1)?;
    let noise_keys2 = NoiseKeypair::<X25519Spec>::new().into_authentic(&id_keys2)?;

    let ping_protocol1 = ping::Behaviour::new(PingConfig::new().with_keep_alive(true));
    let ping_protocol2 = ping::Behaviour::new(PingConfig::new().with_keep_alive(true));


    let transport1 = MemoryTransport::default()
        .upgrade(upgrade::Version::V1)
        .authenticate(NoiseConfig::xx(noise_keys1).into_authenticated())
        .multiplex(mplex::MplexConfig::new())
        .boxed();

    let transport2 = MemoryTransport::default()
        .upgrade(upgrade::Version::V1)
        .authenticate(NoiseConfig::xx(noise_keys2).into_authenticated())
        .multiplex(mplex::MplexConfig::new())
        .boxed();

    let mut swarm1 = SwarmBuilder::new(transport1, ping_protocol1, PeerId::from(id_keys1.public()))
        .executor(Box::new(|fut| { tokio::spawn(fut); }))
        .build();

    let mut swarm2 = SwarmBuilder::new(transport2, ping_protocol2, PeerId::from(id_keys2.public()))
        .executor(Box::new(|fut| { tokio::spawn(fut); }))
        .build();

    let addr1: Multiaddr = "/memory/1".parse()?;
    swarm1.listen_on(addr1.clone())?;
    swarm2.dial(addr1)?;

    let mut events1 = 0;
    let mut events2 = 0;

    loop {
        tokio::select! {
            event = swarm1.next() => match event {
                Some(SwarmEvent::Behaviour(ping::Event { peer, result })) => {
                    println!("Node 1 received ping from {:?} with result {:?}", peer, result);
                    events1 += 1;
                    if events1 > 1 && events2 > 1 {
                        break;
                    }
                }
                _ => {}
            },
            event = swarm2.next() => match event {
                Some(SwarmEvent::Behaviour(ping::Event { peer, result })) => {
                    println!("Node 2 received ping from {:?} with result {:?}", peer, result);
                    events2 += 1;
                    if events1 > 1 && events2 > 1 {
                        break;
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}