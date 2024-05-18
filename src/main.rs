use std::{collections::HashSet, fmt::Write, sync::{Arc, Mutex}};
use k256::{elliptic_curve::{sec1::ToEncodedPoint, group::GroupEncoding}, ProjectivePoint, Scalar, AffinePoint};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use libp2p::{
    core::upgrade, futures::{executor::block_on, StreamExt}, identity, mdns::{Mdns, MdnsConfig, MdnsEvent}, mplex, noise::{Keypair as NoiseKeypair, NoiseConfig, X25519Spec}, ping::{Ping, PingConfig}, swarm::{NetworkBehaviour, SwarmBuilder, SwarmEvent,}, tcp::TcpConfig, yamux, PeerId, Swarm, Transport
};
use tokio::{sync::Mutex as AsyncMutex, time::{self, Duration}};

#[macro_use]
extern crate lazy_static;
lazy_static! {
    // generator point
    pub static ref POINT_G: AffinePoint = k256::AffinePoint::GENERATOR;
    // Indentity
    pub static ref POINT_I: AffinePoint = k256::AffinePoint::IDENTITY;
    // known point P on the curve
    pub static ref POINT_P: ProjectivePoint = *POINT_G * Scalar::from(100u32);
    // public key of the recovered key. this should be updated by the proover
    pub static ref POINT_B: Mutex<ProjectivePoint> = Mutex::new(*POINT_G * Scalar::from(1u32));

}

const TOTAL: usize = 4;
const THRESHOLD: usize = 3;


// Serialize is implemented for AffinePoint and Scalar with serde feature
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Proof {
    point_a: AffinePoint,
    scalar_s: Scalar,
    point_xp: AffinePoint,
    point_rp: AffinePoint,
}

// to_string() implementaio for Proof struct
impl std::fmt::Display for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let point_a_hex = hex::encode(self.point_a.to_bytes().as_slice());
        let scalar_s_hex = hex::encode(self.scalar_s.to_bytes().as_slice());
        let point_xp_hex = hex::encode(self.point_xp.to_bytes().as_slice());
        let point_rp_hex = hex::encode(self.point_rp.to_bytes().as_slice());

        write!(f, "Proof {{\n  point_a: {},\n  scalar_s: {},\n  point_xp: {},\n  point_rp: {}\n}}", 
            point_a_hex, scalar_s_hex, point_xp_hex, point_rp_hex)
    }
}

impl Proof {
    fn new(point_a: AffinePoint, scalar_s: Scalar, point_xp: AffinePoint, point_rp: AffinePoint) -> Self {
        Proof {
            point_a,
            scalar_s,
            point_xp,
            point_rp,
        }
    }
}

// struct for block
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Block {
    index: usize,
    timestamp: i64,
    proof: Proof,
    previous_hash: String,
    data: String,
}

impl Block {
    fn new(index: usize, timestamp: i64, proof: Proof, previous_hash: String, data: String) -> Self {
        Block {
            index,
            timestamp,
            proof,
            previous_hash,
            data,
        }
    }

    fn calculate_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.index.to_string().as_bytes());
        hasher.update(self.timestamp.to_string().as_bytes());
        hasher.update(self.proof.to_string().as_bytes());
        hasher.update(self.previous_hash.as_bytes());
        hasher.update(self.data.as_bytes());

        let hash_result = hasher.finalize();
        let mut hash_str = String::new();
        for byte in hash_result {
            write!(&mut hash_str, "{:02x}", byte).unwrap();
        }
        hash_str
    }

    async fn mine_block(total_parts: usize, threshold: usize) -> Proof {
        
        let mut validated = false;
        let mut proof = Proof::new(*POINT_I, Scalar::ONE, *POINT_I, *POINT_I); // placeholder

        while !validated {

            let (scalar_x, pub_key) = get_recovered_key();
            *POINT_B.lock().unwrap() = pub_key; // update the public key

            // generate random scalar r and point A
            let scalar_r = Scalar::from(56u32);
            let point_a = *POINT_G * scalar_r;

            // Calculate xP, rP and 
            let point_xp = *POINT_P * scalar_x;
            let point_rp = *POINT_P * scalar_r;

            let mut hasher = Sha256::new();

            hasher.update(point_xp.to_encoded_point(true));
            hasher.update(point_rp.to_encoded_point(true));
            hasher.update(point_a.to_encoded_point(true));
            let hash = hasher.finalize();

            // Convert the first 4 bytes of the SHA-256 output to u32
            // here we are dropping the last 4 bytes
            let bytes = hash[0..16].try_into().unwrap();
            let output: u128 = u128::from_be_bytes(bytes);

            // Calculate c = H(xP, rP, A)
            let scalar_c = Scalar::from(output);

            // Caclulate s = r + c.x
            let scalar_s = scalar_r + scalar_c * scalar_x;


            proof = Proof {
                point_a: point_a.to_affine(), 
                scalar_s: scalar_s, 
                point_xp: point_xp.to_affine(),
                point_rp: point_rp.to_affine(), 
            };

            validated = Self::valid_proof(&proof);

        }
        tokio::time::sleep(Duration::from_secs(5)).await;
        
        proof

    }

    fn valid_proof(proof: &Proof) -> bool {
        let mut hasher = Sha256::new();

        hasher.update(proof.point_xp.to_encoded_point(true));
        hasher.update(proof.point_rp.to_encoded_point(true));
        hasher.update(proof.point_a.to_encoded_point(true));
        let hash = hasher.finalize();

        // Convert the first 4 bytes of the SHA-256 output to u32
        // here we are dropping the last 4 bytes
        let bytes = hash[0..16].try_into().unwrap();
        let output: u128 = u128::from_be_bytes(bytes);

        // Calculate c = H(xP, rP, A)
        let scalar_c = Scalar::from(output);

        // / Calculate s.G
        let point_sg = *POINT_G * proof.scalar_s;
        // Calculate A + c.B
        let point_acb = *POINT_B.lock().unwrap() * scalar_c + proof.point_a;
        // Calculate s.P
        let point_sp = *POINT_P * proof.scalar_s;
        // Calculate rP + c.xP
        let point_rpcxp = proof.point_xp * scalar_c + proof.point_rp;

    if point_sg == point_acb && point_sp == point_rpcxp{
        println!("Proof is valid:)");
        return true
    } 

    println!("Proof validation unsuccessful :(");
    false

    }

    


    // }
}

// struct for the blockchain
#[derive(Debug, Serialize, Deserialize)]
struct Blockchain {
    chain: Vec<Block>,
    total_parts: usize,
    threshold: usize,
    height: usize,
}

impl Blockchain {
    fn new() -> Self {
        let mut blockchain = Blockchain {
            chain: Vec::new(),
            total_parts: TOTAL,
            threshold: THRESHOLD,
            height: 0,

        };

        blockchain.create_genesis_block();
        blockchain
    }

    // genesis block representing the starting block
    fn create_genesis_block(&mut self) {

        let genesis_proof = Proof{point_a: *POINT_I, scalar_s: Scalar::ONE, point_xp: *POINT_I, point_rp: *POINT_I};
        let genesis_block = Block::new(0, chrono::Utc::now().timestamp(), genesis_proof, String::new(), "Genesis Block".to_string());
        self.chain.push(genesis_block);
        
    }

    // add a mined block to an existing chain
    async fn add_block(&mut self, data: String) {
        println!("Mining new block...");
        let last_block = self.chain.last().unwrap();
        let new_block = Block::new(
            last_block.index + 1,
            chrono::Utc::now().timestamp(),
            Block::mine_block(TOTAL, THRESHOLD).await,
            last_block.calculate_hash(),
            data,
        );

        println!("Calculate hash is {}", last_block.calculate_hash());
        let current_height = last_block.index;
        self.chain.push(new_block);
        println!("Block mined!");
        println!("Total blocks mined: {}", current_height);
        
        
    }

    // async fn add_received_block(&mut self, new_block: Block) {
    //     println!("Adding a received block...");
    //     // let last_block = self.chain.last().unwrap();
    //     self.chain.push(new_block);
    //     println!("Received block added!");
    // }

    fn get_latest_index(&self) -> usize {
        self.chain.last().unwrap().index
    }

    fn get_last_block(&self) -> Block {

        // there is always at least one block because of the genesis block
        self.chain.last()
            .unwrap()
            .clone()

    }
}

struct App {
    swarm: Swarm<Mdns>,
    blockchain: Arc<AsyncMutex<Blockchain>>,
    peers: Arc<AsyncMutex<HashSet<PeerId>>>,
}

impl App {

    pub async fn new()-> Result<(Self), Box<dyn std::error::Error>> {
        // Generate a key pair for this node.
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        println!("Local node identity: {:?}", local_peer_id);

        let noise_keys = NoiseKeypair::<X25519Spec>::new().into_authentic(&local_key)?;
        let noise = NoiseConfig::xx(noise_keys).into_authenticated();

        // Set up a TCP transport with noise encryption and multiplexing via yamux or mplex.
        let transport = TcpConfig::new()
            .upgrade(upgrade::Version::V1)
            .authenticate(noise)
            .multiplex(upgrade::SelectUpgrade::new(yamux::YamuxConfig::default(), mplex::MplexConfig::new()))
            .boxed();

        // Create a Swarm to manage peers and events.
        let mut swarm = {
            let mdns = Mdns::new(MdnsConfig::default()).await?;
            SwarmBuilder::new(transport, mdns, local_peer_id)
                .executor(Box::new(|fut| { tokio::spawn(fut); }))
                .build()
        };

        Swarm::listen_on(&mut swarm, "/ip4/0.0.0.0/tcp/0".parse()?)?;


        Ok(Self {
            swarm: swarm,
            blockchain: Arc::new(AsyncMutex::new(Blockchain::new())),
            peers: Arc::new(AsyncMutex::new(HashSet::new())),
        })


    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {

        let blockchain = self.blockchain.clone();

        tokio::spawn(async move{
            let mut interval = time::interval(Duration::from_secs(6)); // mining interval
            loop {
                interval.tick().await;
                let mut bc = blockchain.lock().await;
                bc.add_block("Sample data".to_string()).await;
            }
        });

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_event(event).await;
                }
            }
        }
    }

    async fn handle_event(&self, event: SwarmEvent<MdnsEvent, void::Void>) {
        match event {
            SwarmEvent::Behaviour(event) => match event {
                MdnsEvent::Discovered(peers) => {
                    let mut peers_guard = self.peers.lock().await;
                    for (peer, _) in peers {
                        if peers_guard.insert(peer) {
                            println!("New peer discovered: {:?}", peer);
                        }
                    }
                },
                MdnsEvent::Expired(peers) => {
                    let mut peers_guard = self.peers.lock().await;
                    for (peer, _) in peers {
                        peers_guard.remove(&peer);
                    }
                }
            },
            _ => {}
        }
    }

    // async fn handle_incoming_block(&mut self, swarm: &mut Swarm<MyBehaviour>, block: Block) {
    //     if validate_block(&block) {
    //         let blockchain = self.blockchain.clone();
    //         let mut bc = blockchain.lock().await;
    //         // Check if this block extends the longest chain
    //         if block.index > bc.get_latest_index() {
    //             bc.add_received_block(block);
                
    //             // Broadcast this block to other peers
    //             self.broadcast_block(swarm, &block).await;
    //         } else {
    //             // The block is valid but doesn't extend the longest chain
    //             println!("Received block is not part of the longest chain.");
    //         }
    //     } else {
    //         println!("Received invalid block.");
    //     }

    // }

    // async fn broadcast_block(&self, swarm: &mut Swarm<MyBehaviour>, block: Block) {
    //     // This would use libp2p pubsub or similar to broadcast the block
    //     // For example, using gossipsub to broadcast the block
    //     let message = block
    //     swarm.floodsub.publish(TOPIC, message);
    // }

    

    
    
}

// fn validate_block(block: &Block) -> bool {
//     // we validate only the proof for now
//     // TODO: Signature validation, Transaction validation
//     Block::valid_proof(&block.proof)
// }

fn get_recovered_key() -> (Scalar, ProjectivePoint) {
    // Define scalar x
    let x = Scalar::from(43u32);

    // get a list of scalars from the sensed data
    // add them together to create the key
    // generate and publish the public key
    // return the keys

    // Calculate points B s.t. B = xG
    let b = *POINT_G * x;

    (x, b)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)] // Adjust the number of threads based on your needs
async fn main() {

    // if let Err(e) = run().await {
    //     eprintln!("Error: {:?}", e);
    // }

    // let mut app = App::new().await.expect("Failed to create app");
    // if let Err(e) = app.run().await {
    //     eprintln!("Error running app: {:?}", e);
    // }

    let mut app = App::new().await;
    let _ = app.unwrap().run().await;

    // let mut blockchain = Blockchain::new();

    
    // println!("Enter a new data to add to the block:");
    // let mut data = String::new();
    // std::io::stdin().read_line(&mut data).expect("Failed to read line");

    // blockchain.add_block(data.trim().to_string());

    // for block in blockchain.chain.iter() {
    //     // println!("{:?}", block);
    //     println!("Hash: {}", block.calculate_hash());
    // }

}

