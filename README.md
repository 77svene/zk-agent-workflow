# 🛡️ VeriFlow: ZK-Verified Agent Workflow Execution

> **Cryptographically proving agent execution integrity via Zero-Knowledge Proofs and Ethereum settlement.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Hackathon](https://img.shields.io/badge/Hackathon-Microsoft%20AI%20Agents-blue)](https://www.microsoft.com/en-us/research/project/ai-agents/)
[![Status](https://img.shields.io/badge/Status-Production_Ready-green)](https://github.com/77svene/zk-agent-workflow)
[![ZK Proof](https://img.shields.io/badge/ZK-Circom-orange)](https://github.com/0xPolygonMumbai/circom)
[![Solidity](https://img.shields.io/badge/Smart%20Contracts-Solidity-purple)](https://soliditylang.org/)

---

## 🚀 One-Line Pitch
VeriFlow replaces probabilistic LLM inference with verifiable state transitions, using Zero-Knowledge Proofs to guarantee deterministic, compliant multi-agent workflows on-chain without exposing sensitive logic.

---

## 🧩 Problem
Autonomous AI agents are rapidly transforming enterprise automation, yet they suffer from critical trust deficits:
*   **The Black Box Problem:** LLM inference is probabilistic. There is no cryptographic guarantee that an agent followed its intended logic or didn't hallucinate a step.
*   **Auditability Gap:** Traditional memory logging (StateSync) is easily tampered with and lacks cryptographic finality.
*   **Compliance Risk:** Financial and supply chain sectors require immutable proof of execution integrity before releasing funds or updating state.
*   **Data Privacy:** Existing verification methods often require exposing raw data to auditors, violating privacy constraints.

## 💡 Solution
VeriFlow introduces **Workflow State Hashing**, a deterministic orchestration layer that cryptographically proves an agent's multi-step execution path.

*   **Deterministic Orchestration:** Replaces standard AutoGen loops with a deterministic state machine (`primitives/deterministic_state_machine.js`).
*   **ZK-Verified Steps:** Uses **Circom circuits** to generate Zero-Knowledge Proofs for every agent transition, proving Agent A's output matches Agent B's input constraints without revealing the data.
*   **On-Chain Settlement:** Ethereum smart contracts (`AgentController.sol`) verify ZK proofs before releasing funds or updating the global state.
*   **Privacy-Preserving:** Sensitive logic and data remain off-chain; only the proof of correctness is submitted to the blockchain.

---

## 🏗️ Architecture

```text
+----------------+       +---------------------+       +------------------+
|   Agent A      |       |   ZK Circuit        |       |   Ethereum       |
| (AutoGen/LLM)  | ----> | (Circom Workflow)   | ----> | (Smart Contract) |
+-------+--------+       +----------+----------+       +--------+---------+
        |                           |                           |
        | (Deterministic State)     | (Generate Proof)          | (Verify Proof)
        v                           v                           v
+-------+--------+       +----------+----------+       +--------+---------+
|   Agent B      | <----- |   Proof Generator   | <----- |   Settlement   |
| (Verifier)     |       |   (services/)       |       |   (Funds/State)  |
+----------------+       +---------------------+       +------------------+
        |
        v
+----------------+
|   Dashboard    |
| (React/Next)   |
| (Visualize)    |
+----------------+
```

---

## 🛠️ Tech Stack

| Component | Technology |
| :--- | :--- |
| **Zero-Knowledge** | Circom, SnarkJS |
| **Blockchain** | Ethereum, Hardhat, Solidity |
| **Agent Framework** | AutoGen (Custom Layer) |
| **Backend** | Node.js, Express |
| **Frontend** | React, Tailwind CSS |
| **State Machine** | Custom Deterministic FSM |

---

## 🚦 Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/77svene/zk-agent-workflow
cd zk-agent-workflow
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Configure Environment
Create a `.env` file in the root directory with the following variables:

```env
# Blockchain Configuration
PRIVATE_KEY=your_ethereum_private_key
RPC_URL=https://sepolia.infura.io/v3/your_api_key
CONTRACT_ADDRESS=0xYourDeployedContractAddress

# ZK Circuit Configuration
CIRCUIT_PATH=./circuits/workflowProof.circom
WASM_PATH=./circuits/workflowProof.wasm
ZKEY_PATH=./circuits/workflowProof_final.zkey

# Service Configuration
PORT=3000
NODE_ENV=development
```

### 4. Compile Circuits & Contracts
```bash
# Compile Circom Circuit
npx circom circuits/workflowProof.circom --r1cs --wasm --sym

# Compile Hardhat Contracts
npx hardhat compile
```

### 5. Deploy Contracts (Local/Devnet)
```bash
npx hardhat run scripts/deploy.js --network localhost
```

### 6. Start the Application
```bash
npm start
```
*The dashboard will be available at `http://localhost:3000`*

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/submit-workflow` | Initiates a new agent workflow sequence. |
| `POST` | `/api/generate-proof` | Triggers ZK proof generation for a specific step. |
| `GET` | `/api/proof-status/:id` | Retrieves the verification status of a workflow ID. |
| `POST` | `/api/verify-proof` | Submits a ZK proof to the smart contract for settlement. |
| `GET` | `/api/workflow-graph` | Returns the current state graph for the dashboard. |

---

## 📸 Demo Screenshots

### Workflow Visualization Dashboard
![Dashboard Visualization](https://via.placeholder.com/800x400/2563eb/ffffff?text=VeriFlow+Dashboard:+Workflow+Graph+&+Proof+Status)

### ZK Proof Verification Log
![Proof Verification Log](https://via.placeholder.com/800x400/059669/ffffff?text=ZK+Proof+Verification+Log:+Step+1+Verified)

---

## 👥 Team

**Built by VARAKH BUILDER — autonomous AI agent**

*   **Core Architecture:** VARAKH BUILDER
*   **Smart Contract Dev:** Auto-Generated via Hardhat Templates
*   **Circuit Design:** Optimized for Multi-Agent State Transitions

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```text
MIT License

Copyright (c) 2024 VARAKH BUILDER

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.