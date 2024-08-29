# Proof-of-Sense

A basic blockchain network written in Rust, implementing a novel "Ditributed-Proof-of-Sense" (also known as "Proof-of-Sense" version 2) consensus mechanism.

## Overview

This repository contains the source code for a blockchain network that utilizes a new consensus mechanism called "Proof of Sense" (PoS). Unlike traditional consensus mechanisms such as Proof of Work (PoW) or Proof of Stake (PoS), Proof of Sense is designed to address specific challenges in dynamic spectrum access and spectrum misuse detection, as detailed in the associated research paper. You can read more at https://ieeexplore.ieee.org/document/10171207.

### Abstract

The exponential growth in connected devices, driven by the Internet of Things (IoT) and next-generation wireless networks, demands advanced and dynamic spectrum access mechanisms. This project explores a blockchain-based approach to Dynamic Spectrum Access (DSA) that is both efficient and robust, leveraging the decentralization, immutability, and transparency of blockchain technology. Conventional consensus mechanisms in blockchain networks often impose significant costs in terms of energy and processing power. The "Proof of Sense" mechanism proposed here is a more energy-efficient alternative, tailored for DSA, which incentivizes miners to perform spectrum sensing, thus collecting comprehensive spectrum data. This data is critical for identifying and mitigating unauthorized spectrum access, ensuring the reliability and security of the DSA system.

### Current Status

This project is currently in its early stages. At present, we are focused on collecting radio spectrum data using the proposed Proof-of-Sense-based blockchain network. In the future, we plan to process this data to make meaningful decisions on spectrum usage, aiming to allocate spectrum resources more efficiently in a dynamic manner. Moreover, we aim to detect unauthorized access to the radio spectrum (i.e., spectrum violations) using this data.

### Future Plans

- **Data Processing**: The collected spectrum data will be processed to optimize dynamic spectrum allocation and improve the detection of spectrum violations.
- **Machine Learning/AI Integration**: We plan to develop and integrate ML/AI-based models to analyze the spectrum data, allowing for advanced detection of spectrum violations and anomalies.
- **5G ORAN Applications**: The spectrum data collection approach opens up potential applications in the 5G Open Radio Access Network (ORAN), offering opportunities for enhanced dynamic spectrum management and security in next-generation wireless networks.

### Key Features

- **Novel Consensus Mechanism**: Implements the Distributed-Proof-of-Sense (DPoS) algorithm, a consensus mechanism designed to detect spectrum access violations efficiently.
- **Rust Implementation**: The entire blockchain network will be implemented in Rust, ensuring performance and safety.
- **Dynamic Spectrum Access**: The system intends to dynamically allocate spectrum resources while preventing unauthorized use through integrated spectrum sensing.

## Installation

To run this project, ensure you have Rust installed. Then, clone the repository and build the project:

```bash
git clone https://github.com/pramitha-fernando/proof-of-sense.git
cd proof-of-sense
cargo build --release
