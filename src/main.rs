use csv::ReaderBuilder;
use k256::{
    elliptic_curve::{group::GroupEncoding, rand_core::block, sec1::ToEncodedPoint},
    AffinePoint, ProjectivePoint, Scalar,
};
use libp2p::{
    core::upgrade,
    futures::{executor::block_on, future::ok, StreamExt},
    gossipsub::{
        Gossipsub, GossipsubConfig, GossipsubEvent, IdentTopic as Topic, MessageAuthenticity,
        RawGossipsubMessage, ValidationMode,
    },
    identity,
    mdns::{Mdns, MdnsConfig, MdnsEvent},
    mplex,
    noise::{Keypair as NoiseKeypair, NoiseConfig, X25519Spec},
    ping::{Ping, PingConfig},
    swarm::{NetworkBehaviour, SwarmBuilder, SwarmEvent},
    tcp::TcpConfig,
    yamux, PeerId, Swarm, Transport,
};
use reqwest::{self, Body, Client, multipart};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{
    digest::generic_array::{typenum::U32, GenericArray},
    Digest, Sha256,
};
use std::{error::Error, fs::OpenOptions, io::{Read, Write}, path::Path};
use std::io::{self, BufRead, BufReader};
use std::process::{Command, Stdio};
use std::{
    collections::HashSet,
    fmt::Write as FileWrite,
    fs::File,
    ptr::read,
    sync::{Arc, Mutex},
};
use tokio::{
    sync::Mutex as AsyncMutex,
    time::{self, Duration},
};

use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

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

const NODEID: usize = 1; // change node id from here

const TOTAL: usize = 4;
const THRESHOLD: usize = 3;


type IPFSHash = String;

#[derive(Serialize, Deserialize, Debug)]
struct DataPoint {
    node_id: usize,
    power_reading: Vec<PowerReading>,
    total_nodes: usize,
    threshold: usize,
    recovered_keys: usize,
}

#[derive(Serialize, Deserialize, Debug)]
struct PowerReading {
    reading_date: String,
    reading_time: String,
    hz_low: f64,
    hz_high: f64,
    bin_width: f64,
    no_samples: i32,
    power_db: Vec<f32>,
}

// Serialize is implemented for AffinePoint and Scalar with serde feature
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Proof {
    point_a: AffinePoint,
    scalar_s: Scalar,
    point_xp: AffinePoint,
    point_rp: AffinePoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Transaction {
    seller: String,
    buyer: String,
    metadata: String,
}

// to_string() implementaio for Proof struct
impl std::fmt::Display for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let point_a_hex = hex::encode(self.point_a.to_bytes().as_slice());
        let scalar_s_hex = hex::encode(self.scalar_s.to_bytes().as_slice());
        let point_xp_hex = hex::encode(self.point_xp.to_bytes().as_slice());
        let point_rp_hex = hex::encode(self.point_rp.to_bytes().as_slice());

        write!(
            f,
            "Proof {{\n  point_a: {},\n  scalar_s: {},\n  point_xp: {},\n  point_rp: {}\n}}",
            point_a_hex, scalar_s_hex, point_xp_hex, point_rp_hex
        )
    }
}

impl Proof {
    fn new(
        point_a: AffinePoint,
        scalar_s: Scalar,
        point_xp: AffinePoint,
        point_rp: AffinePoint,
    ) -> Self {
        Proof {
            point_a,
            scalar_s,
            point_xp,
            point_rp,
        }
    }
}

#[derive(Debug, Clone)]
struct ReceivedData {
    node_id: usize,
    counter: usize,
    key: Scalar,
    hash: GenericArray<u8, U32>, // sha256 output is 32bytes
}

impl ReceivedData {
    fn new(node_id: usize, counter: usize, key: Scalar, hash: GenericArray<u8, U32>) -> Self {
        ReceivedData {
            node_id,
            counter,
            key,
            hash,
        }
    }

    fn verify_key_hash(&self) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(self.key.to_bytes());
        let hash_result = hasher.finalize();

        hash_result == self.hash
    }
}

// struct for block
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Block {
    index: usize,
    timestamp: i64,
    proof: Proof,
    previous_hash: String,
    transactions: String,
    spectrum_data: Vec<IPFSHash>,
}

impl Block {
    fn new(
        index: usize,
        timestamp: i64,
        proof: Proof,
        previous_hash: String,
        transactions: String,
        spectrum_data: Vec<IPFSHash>,
    ) -> Self {
        Block {
            index,
            timestamp,
            proof,
            previous_hash,
            transactions,
            spectrum_data,
        }
    }

    fn calculate_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.index.to_string().as_bytes());
        hasher.update(self.timestamp.to_string().as_bytes());
        hasher.update(self.proof.to_string().as_bytes());
        hasher.update(self.previous_hash.as_bytes());
        hasher.update(self.transactions.as_bytes());

        for data in &self.spectrum_data {
            hasher.update(data.as_bytes());
        }
        
        let hash_result = hasher.finalize();
        let mut hash_str = String::new();
        for byte in hash_result {
            write!(&mut hash_str, "{:02x}", byte).unwrap();
        }
        hash_str
    }

    async fn mine_block(total_key_parts: usize, threshold: usize) -> Proof {
        let mut validated = false;
        let mut proof = Proof::new(*POINT_I, Scalar::ONE, *POINT_I, *POINT_I); // placeholder

        while !validated {
            if let Ok((scalar_x, pub_key)) = get_recovered_key(threshold, total_key_parts).await {
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
            } else {
                eprintln!("Not enough recovered keys yet!");
                // time::sleep(Duration::from_secs(5)).await; 
            }
        }
        // tokio::time::sleep(Duration::from_secs(5)).await;

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

        if point_sg == point_acb && point_sp == point_rpcxp {
            println!("Proof is valid:)");
            return true;
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
        let genesis_proof = Proof {
            point_a: *POINT_I,
            scalar_s: Scalar::ONE,
            point_xp: *POINT_I,
            point_rp: *POINT_I,
        };
        let genesis_block = Block::new(
            0,
            chrono::Utc::now().timestamp(),
            genesis_proof,
            String::new(),
            "Genesis Block".to_string(),
            Vec::new(),
        );
        let _ = self.append_block_to_file("blockchain.data", &genesis_block);
        self.chain.push(genesis_block);
    }

    // add a mined block to an existing chain
    async fn add_block(&mut self, transactions: String, spectrum_data: Vec<IPFSHash>) {
        println!("Mining new block...");
        let last_block = self.chain.last().unwrap();

        let new_block = Block::new(
            last_block.index + 1,
            chrono::Utc::now().timestamp(),
            Block::mine_block(TOTAL, THRESHOLD).await,
            last_block.calculate_hash(),
            transactions,
            spectrum_data,
        );

        println!("Calculate hash is {}", last_block.calculate_hash());
        let current_height = last_block.index;
        let _ = self.append_block_to_file("blockchain.data", &new_block);
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
        self.chain.last().unwrap().clone()
    }

    // save the entire blockchain as JSON
    fn save_to_file(&self, filename: &str) -> io::Result<()> {
        let serialized = serde_json::to_string(self)?;
        let mut file = File::create(filename)?;
        file.write_all(serialized.as_bytes())?;
        Ok(())
    }

    // load a seralized JSON blockchain
    fn load_from_file(filename: &str) -> io::Result<Self> {
        let mut file = File::open(filename)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // let blockchain: Blockchain = serde_json::from_str(&contents)?;
        // Ok(blockchain)

        let mut chain = Vec::new();
        let mut last_block_index = 0;

        for line in contents.lines() {
            let block: Block = serde_json::from_str(line)?;
            last_block_index = block.index;
            chain.push(block);
        }

        Ok(
            Blockchain { 
                chain, 
                total_parts: TOTAL,
                threshold: THRESHOLD,
                height: last_block_index
            }
        )
    }

    // append to existing blockchain
    fn append_block_to_file(&self, filename: &str, block: &Block) -> io::Result<()> {
        // check if the file exists
        if Path::new(filename).exists() {
            let mut file = OpenOptions::new()
                                 .append(true)
                                 .open(filename)?;

            // append the serialized block to the file
            let serialized_block = serde_json::to_string(block)?;
            writeln!(file, "{}", serialized_block)?;
        } else {
            // if the file doesn't exists, create it and write the block
            let mut file = File::create(filename)?;
            // write the serialzed block to the new file
            let serialized_block = serde_json::to_string(block)?;
            writeln!(file, "{}", serialized_block)?;
        }

        Ok(())
    }


}

struct App {
    swarm: Swarm<Mdns>,
    blockchain: Arc<AsyncMutex<Blockchain>>,
    peers: Arc<AsyncMutex<HashSet<PeerId>>>,
}

impl App {
    pub async fn new() -> Result<(Self), Box<dyn std::error::Error>> {
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
            .multiplex(upgrade::SelectUpgrade::new(
                yamux::YamuxConfig::default(),
                mplex::MplexConfig::new(),
            ))
            .boxed();

        // set up gossipsub
        // let gossipsub_config = GossipsubConfig::default();
        // let mut gossipsub = Gossipsub::new(MessageAuthenticity::Signed(local_key.clone()),gossipsub_config)
        //     .expect("Correct Gossipsub instantiation");
        // // subscrive to a topic
        // let topic = Topic::new("blocks");
        // gossipsub.subscribe(&topic).expect("Subscription to 'blocks' topic");

        // Create a Swarm to manage peers and events.
        let mut swarm = {
            let mdns = Mdns::new(MdnsConfig::default()).await?;
            SwarmBuilder::new(transport, mdns, local_peer_id)
                .executor(Box::new(|fut| {
                    tokio::spawn(fut);
                }))
                .build()
        };

        Swarm::listen_on(&mut swarm, "/ip4/0.0.0.0/tcp/0".parse()?)?;

        let choice = get_user_choice();

        let blockchain = match choice {

            1 => {
                let filename = "blockchain.data";

                if Path::new(filename).exists() {
                    let loaded_blockchain = Blockchain::load_from_file(filename)?;
                    println!("Loaded blockchain with {} blocks!", loaded_blockchain.height);
                    Arc::new(AsyncMutex::new(loaded_blockchain))
                } else {
                    println!("No existing blockchain found. Starting a new one.");
                    Arc::new(AsyncMutex::new(Blockchain::new()))
                }
            }

            _ => {
                let filename = "blockchain.data";

                if Path::new(filename).exists() {
                    std::fs::remove_file(filename)?;
                    println!("Existing blockchain data cleaned!");
                }
                Arc::new(AsyncMutex::new(Blockchain::new()))
            }
            
        };

        Ok(Self {
            swarm,
            blockchain,
            peers: Arc::new(AsyncMutex::new(HashSet::new())),
        })
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let blockchain = self.blockchain.clone();

        tokio::spawn(async move {
            let mut rng = StdRng::from_entropy();

            // let mut interval = time::interval(Duration::from_secs(6)); // mining interval
            loop {
                // interval.tick().await;

                let random_secs = rng.gen_range(4..=10); // Random number between 4 and 10

                let mut spectrum_data: Vec<IPFSHash> = Vec::new(); // Initialize an empty vector to store IPFS hashes


                // Run the hackrf_sweep random_secs times
                for _ in 0..random_secs {
                    // minimum and maximum frequencies in MHz
                    let frequency = "2400:2600";
                    // RX RF amplifier 1=Enable, 0=Disable
                    let amp_enable = "0";
                    // RX LNA (IF) gain, 0-40dB, 8dB steps
                    let if_gain_db = "40";
                    // RX VGA (baseband) gain, 0-62dB, 2dB steps
                    let bb_gain_db = "24";
                    // in_width] # FFT bin width (frequency resolution) in Hz, 2445-5000000
                    let bin_width = "1000000";

                    let result = hackrf_sweep(frequency, amp_enable, if_gain_db, bb_gain_db, bin_width).await;

                    match result {
                        Ok(ipfs_hash) => {
                            spectrum_data.push(ipfs_hash);
                        },
                        Err(e) => {
                            eprintln!("Failed to get IPFS hash: {}", e);
                        },
                    }

                    // Wait for 1 second before the next hackrf_sweep
                    time::sleep(Duration::from_secs(1)).await;
                }

                let mut bc = blockchain.lock().await;

                let transactions = "Sample data".to_string();
                bc.add_block(transactions, spectrum_data).await;

                let last_block = bc.get_last_block();
                let data = serde_json::to_string(&last_block);

                match data {
                    Ok(json) => {
                        let _ = send_data(json, "block").await;
                    }
                    Err(e) => eprintln!("Failed to serialize block: {}", e),
                }

                
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
                }
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
    //     let topic = Topic::new("blocks");
    //     let message = serde_json::to_string(&block).unwrap();
    // }
}

async fn hackrf_sweep(
    frequency: &str,
    amp_enable: &str,
    if_gain_db: &str,
    bb_gain_db: &str,
    bin_width: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let output = Command::new("hackrf_sweep")
        .args([
            "-f", frequency, "-a", amp_enable, "-l", if_gain_db, "-g", bb_gain_db, "-w", bin_width,
            "-1", // one shot mode
        ])
        .stdout(Stdio::piped()) // Redirects stdout to the file
        .output()?;

    if !output.status.success() {
        eprintln!("Command failed, check your parameters or setup");
        return Ok("".to_string());
    }

    // Process the output 
    let reader = BufReader::new(io::Cursor::new(output.stdout));

    let mut power_reading: Vec<PowerReading> = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split(',').collect();
        // check if reading has at least one db column (depends on the bid width)
        if parts.len() > 6 {
            let mut power_db: Vec<f32> = Vec::new();

            let total_columns = parts.len();
            let mut column = 5;

            loop {
                column += 1; // db values start from index 6
                if column == total_columns {
                    break;
                }
                power_db.push(parts[column].trim().parse::<f32>().unwrap());
            }

            let reading = PowerReading {
                reading_date: parts[0].trim().to_string(),
                reading_time: parts[1].trim().to_string(),
                hz_low: parts[2].trim().parse::<f64>().unwrap(),
                hz_high: parts[3].trim().parse::<f64>().unwrap(),
                bin_width: parts[4].trim().parse::<f64>().unwrap(),
                no_samples: parts[5].trim().parse::<i32>().unwrap(),
                power_db: power_db,
            };

            power_reading.push(reading);
        } else {
            eprint!("Something is wrong with reading data from SDR");
        }
    }

    let data_point = DataPoint {
        node_id: NODEID,
        power_reading,
        total_nodes: TOTAL,
        threshold: THRESHOLD,
        recovered_keys: 2,
    };

    // Serialize the data to a JSON string
    let json_data = serde_json::to_string(&data_point)?;
         // Create a multipart form part
    let form = multipart::Form::new()
         .part("file", multipart::Part::text(json_data.clone()).file_name("data.json"));
 

    let _result = send_data(json_data, "data").await;

     // Create a new HTTP client
     let client = Client::new();


     // Send the POST request to the IPFS API with the file
     let response = client
         .post("http://127.0.0.1:5004/api/v0/add") // local IPFS node should be running, default port is 5001
         .multipart(form)
         .send()
         .await?;
 
     // Print the response
     let response_text = response.text().await?;

     // Parse the response text as JSON
    let json: Value = serde_json::from_str(&response_text)?;

    // initiate an empty string for the IPFS Hash
    let mut ipfs_hash: IPFSHash = "".to_string(); 

    // Extract the hash from the JSON
    if let Some(hash) = json.get("Hash") {
        ipfs_hash = hash.to_string();
        // println!("Uploaded file hash: {}", ipfs_hash);
    } else {
        println!("IPFS upload failed");
    }

    Ok(ipfs_hash)
}

async fn send_data(json_data: String, endpoint: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::new();
    let url = "http://127.0.0.1:1880/".to_string() + endpoint;

    let result = client.post(url).body(json_data).send().await;

    match result {
        Ok(response) => {
            // println!("Status {}", response.status());
            Ok(response.status().to_string())
        }
        Err(e) => {
            eprint!("Error {}", e);
            Err(Box::new(e))
        }
    }
}

fn get_user_choice() -> u8 {
    println!("Select an option:");
    println!("0: Start a new blockchain (default)");
    println!("1: Load existing blockchain");

    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read input");
    let choice: u8 = input.trim().parse().unwrap_or(0);
    choice
}

fn validate_block(block: &Block) -> bool {
    // we validate only the proof for now
    // TODO: Signature validation, Transaction validation
    Block::valid_proof(&block.proof)
}

async fn get_recovered_key(threshold: usize, total_keys: usize) -> Result<(Scalar, ProjectivePoint), String> {
    let mut hasher = Sha256::new();
    hasher.update(&[0u8]);
    let hash_result = hasher.finalize();

    let empty_rx_data = ReceivedData::new(0, 0, Scalar::from(0u32), hash_result);

    let mut rx_data = vec![empty_rx_data; total_keys]; //initiate recovered key vector to all zeros. Vec size is total keys

    let metadata = std::fs::metadata("sample_keys.txt").unwrap();
    if metadata.len() == 0 {
        return Err(From::from("The file is empty."));
    }

    let file = File::open("sample_keys.txt").unwrap();
    let mut reader = ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b',') // delimiter
        .from_reader(file);

    let mut index = 0;
    for result in reader.records() {
        if index + 1 > total_keys {
            break;
        }
        // println!("Index is {}", index);

        let record = result.unwrap();
        // extract node ID
        if let Some(node_id) = record.get(0) {
            let node_id = node_id.trim();
            match node_id.parse::<usize>() {
                Ok(id) => {
                    if let Some(data) = rx_data.get_mut(index) {
                        data.node_id = id;
                    } else {
                        eprintln!("Index out of bounds: {}", index);
                    }
                }
                Err(e) => eprintln!("Failed to parse '{}' as integer: {}", node_id, e),
            }
        }

        // extract session id
        if let Some(session_id) = record.get(1) {
            let session_id = session_id.trim();
            match session_id.parse::<usize>() {
                Ok(id) => {
                    if let Some(data) = rx_data.get_mut(index) {
                        data.counter = id;
                    } else {
                        eprintln!("Index out of bounds: {}", index);
                    }
                }
                Err(e) => eprintln!("Failed to parse '{}' as integer: {}", session_id, e),
            }
        }

        // extract key
        if let Some(key) = record.get(2) {
            let key = key.trim();
            match key.parse::<u32>() {
                Ok(scalar) => {
                    if let Some(data) = rx_data.get_mut(index) {
                        data.key = Scalar::from(scalar);
                    } else {
                        eprintln!("Index out of bounds: {}", index);
                    }
                }
                Err(e) => eprintln!("Failed to parse '{}' as integer: {}", key, e),
            }
        }

        index += 1;
    }

    println!(
        "Found {} out of {} keys. Threhold is set to {}",
        index, total_keys, threshold
    );

    if index < threshold {
        return Err(From::from("Not enough keys"));
    }

    // Define scalar x
    let mut final_key = Scalar::from(0u32);

    for data in rx_data.iter() {
        final_key = final_key + data.key;
    }

    // Calculate points B s.t. B = xG
    let final_public_key = *POINT_G * final_key;

    // send key recovery data
    let recovery_data = json!( {
        "node_id": NODEID,
        "threshold": THRESHOLD,
        "total_nodes": TOTAL,
        "recovered_keys": index,
    });

    let json_data = serde_json::to_string(&recovery_data).unwrap();

    let _ = send_data(json_data, "keys").await;


    Ok((final_key, final_public_key))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    // if let Err(e) = run().await {
    //     eprintln!("Error: {:?}", e);
    // }

    // let mut app = App::new().await.expect("Failed to create app");
    // if let Err(e) = app.run().await {
    //     eprintln!("Error running app: {:?}", e);
    // }

    // let testing = get_recovered_key();

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
