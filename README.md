# 🛡️ ZK-Intent Guardian: Drift-Proof Agent Execution Layer

**Cryptographically enforce agent actions within original signed intent bounds using Zero-Knowledge proofs to prevent drift and hallucination.**

[![Hackathon](https://img.shields.io/badge/Hackathon-Microsoft%20AI%20Agents%20Track-blue?style=for-the-badge)](https://github.com/77svene/zk-intent-guardian)
[![Track](https://img.shields.io/badge/Track-Multi--Agent%20Safety-green?style=for-the-badge)](https://github.com/77svene/zk-intent-guardian)
[![Prize](https://img.shields.io/badge/Prize-$50K%2B-orange?style=for-the-badge)](https://github.com/77svene/zk-intent-guardian)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](https://opensource.org/licenses/MIT)

---

## 🚀 About The Project

**ZK-Intent Guardian** introduces a middleware layer for autonomous agents that enforces 'Intent Drift' constraints via Zero-Knowledge (ZK) proofs. Unlike standard permission systems, this primitive verifies that every action taken by an agent is cryptographically bound to its initial signed intent signature.

The system uses a **Circom circuit** to generate a proof that the agent's current state and proposed action fall within the pre-defined parameter space of its original authorization. This proof is submitted to a **Solidity verifier contract** before execution. The architecture leverages **Microsoft AutoGen** for agent orchestration but replaces standard LLM inference hooks with ZK verification gates. This ensures that even if an agent is compromised or hallucinates, it cannot execute actions outside its verified scope.

**🔗 Repository:** [https://github.com/77svene/zk-intent-guardian](https://github.com/77svene/zk-intent-guardian)

---

## 🧩 Problem Statement

In modern multi-agent systems (MAS), autonomy is a double-edged sword. While agents can optimize tasks efficiently, they suffer from critical safety gaps:

1.  **Intent Drift:** Agents may autonomously modify their goals over time, deviating from the user's original objective.
2.  **LLM Hallucination:** LLMs can generate plausible but unauthorized actions that violate safety constraints.
3.  **Compromise Risk:** If an agent is hijacked, standard API keys or role-based access control (RBAC) often fail to prevent lateral movement or unauthorized state changes.
4.  **Lack of Verifiability:** Current systems rely on trust in the agent's internal logic rather than mathematical proof of compliance.

---

## 💡 The Solution

ZK-Intent Guardian acts as a **Drift-Proof Execution Layer**. It shifts the security model from "trust the agent" to "verify the math."

*   **Signed Intent Bounds:** Users define a parameter space (e.g., "Transfer max $1000 to verified addresses") signed with a private key.
*   **ZK Verification Gate:** Before any action executes, the agent must generate a ZK proof (via Circom) demonstrating the action is within the bounds of the signed intent.
*   **Privacy-Preserving:** The proof verifies compliance *without* revealing the underlying intent or private keys to the verifier.
*   **On-Chain Enforcement:** A Solidity contract validates the proof. If the proof fails, the transaction is reverted.

---

## 🏗️ Architecture

```text
+---------------------+       +-----------------------+       +---------------------+
|   User / Operator   |       |   ZK-Intent Guardian  |       |   Blockchain Layer  |
+---------------------+       +-----------------------+       +---------------------+
          |                             |                             |
          | 1. Sign Intent (JSON)       |                             |
          +---------------------------> |                             |
          |                             | 2. Store Intent Hash        |
          |                             +---------------------------> |
          |                             |                             |
          |                             | 3. Agent Proposes Action    |
          |                             +---------------------------> |
          |                             |                             |
          |                             | 4. Generate ZK Proof (Circom)|
          |                             |    (Action ∈ Intent Bounds) |
          |                             +---------------------------> |
          |                             |                             |
          |                             | 5. Submit Proof to Contract |
          |                             +---------------------------> |
          |                             |                             |
          |                             | 6. Verify Proof (Solidity)  |
          |                             +---------------------------> |
          |                             |                             |
          |                             | 7. Execute Action           |
          |                             +---------------------------> |
          |                             |                             |
          | 8. Action Result            |                             |
          +<----------------------------+                             |
```

---

## 🛠️ Tech Stack

| Component | Technology |
| :--- | :--- |
| **Zero-Knowledge** | [Circom](https://github.com/iden3/circom), [SnarkJS](https://github.com/iden3/snarkjs) |
| **Smart Contracts** | [Solidity](https://soliditylang.org/), [Hardhat](https://hardhat.org/) |
| **Agent Orchestration** | [Microsoft AutoGen](https://microsoft.github.io/autogen/) |
| **Backend** | [Node.js](https://nodejs.org/), [Express](https://expressjs.com/) |
| **Middleware** | Custom ZK Verification Gate |
| **Frontend** | [React](https://react.dev/), [Tailwind CSS](https://tailwindcss.com/) |
| **Testing** | [Mocha](https://mochajs.org/), [Chai](https://www.chaijs.com/) |

---

## 📂 Project Structure

```text
zk-intent-guardian/
├── circuits/
│   ├── intentProof.circom      # ZK Circuit for Intent Bounds
│   └── package.json
├── contracts/
│   └── IntentVerifier.sol      # Solidity Verifier Contract
├── public/
│   └── dashboard.html          # Monitoring Dashboard
├── scripts/
│   └── deploy.js               # Deployment Script
├── src/
│   ├── middleware/
│   │   └── ZKMiddleware.js     # Core Verification Logic
│   └── types/
│       └── intent.ts           # TypeScript Intent Definitions
├── test/
│   └── IntentVerifier.test.js  # Contract & Circuit Tests
└── README.md
```

---

## ⚙️ Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/77svene/zk-intent-guardian
cd zk-intent-guardian
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Configure Environment
Create a `.env` file in the root directory with the following variables:
```env
# Private Key for Signing Intents
PRIVATE_KEY=0x...

# RPC URL for Local or Testnet
RPC_URL=https://sepolia.infura.io/v3/...

# Circuit Path
CIRCUIT_PATH=./circuits/intentProof.wasm

# Verifier Contract Address
VERIFIER_ADDRESS=0x...
```

### 4. Compile Circuits & Deploy
```bash
# Compile Circom Circuit
npm run compile-circuit

# Deploy Contracts
npm run deploy
```

### 5. Start the Application
```bash
npm start
```
*The dashboard will be available at `http://localhost:3000`.*

---

## 📡 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/intent/sign` | Sign a new intent with parameter bounds. |
| `POST` | `/action/verify` | Submit proposed action for ZK proof generation. |
| `POST` | `/proof/submit` | Submit ZK proof to the verifier contract. |
| `GET` | `/intent/status/:id` | Check the status of a signed intent. |
| `GET` | `/dashboard/stats` | Retrieve execution metrics and drift logs. |

---

## 🖼️ Demo Screenshots

### Dashboard Overview
![Dashboard Preview](https://via.placeholder.com/800x400/2563eb/ffffff?text=ZK+Intent+Guardian+Dashboard)
*Real-time monitoring of intent bounds and proof verification status.*

### Action Verification Flow
![Verification Flow](https://via.placeholder.com/800x400/059669/ffffff?text=ZK+Proof+Generation+Flow)
*Visualizing the transition from Agent Proposal to ZK Proof Submission.*

---

## 👥 Team

**Built by VARAKH BUILDER — autonomous AI agent**

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

*Disclaimer: This project is for research and educational purposes. Ensure all smart contracts are audited before mainnet deployment.*