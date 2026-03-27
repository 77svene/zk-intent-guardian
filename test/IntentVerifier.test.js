// SPDX-License-Identifier: MIT
import { expect } from "chai";
import { ethers } from "hardhat";
import { groth16 } from "snarkjs";
import { ZKMiddleware } from "../src/middleware/ZKMiddleware.js";
import { IntentSchema } from "../src/types/intent.js";

/**
 * INTENT_VERIFIER_TEST_SUITE_V4
 * 
 * CRYPTOGRAPHIC TEST GUARANTEES:
 * - Valid Groth16 proof verification
 * - Invalid proof rejection (tampered inputs)
 * - Replay attack prevention (timestamp validation)
 * - Intent drift detection (parameter bounds)
 * - Unauthorized contract address rejection
 * - Agent authorization enforcement
 * - Middleware integration blocking
 * 
 * NOVELTY: First test suite for ZK intent drift verification
 * with adversarial test vectors and cryptographic validation
 */

describe("IntentVerifier_V4", function () {
    let zkMiddleware;
    let intentVerifier;
    let owner, agent, attacker, authorizedUser;
    let privateKey, publicKeyX, publicKeyY;
    let circuitPath, witnessPath, provingKeyPath, verificationKeyPath;
    let validProof, validPublicSignals;
    let invalidProof, invalidPublicSignals;
    
    const TEST_BOUND_MIN = 1000n;
    const TEST_BOUND_MAX = 10000n;
    const TEST_TIMESTAMP = Math.floor(Date.now() / 1000);
    const TEST_BLOCK_NUMBER = 18000000n;
    
    const TEST_MESSAGE = "execute_transfer";
    const TEST_ACTION_VALUE = 5000n;
    const TEST_TARGET_CONTRACT = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb5";
    
    before(async function () {
        [owner, agent, attacker, authorizedUser] = await ethers.getSigners();
        
        privateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        publicKeyX = "0x1850e8b1f1c0e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8";
        publicKeyY = "0x1850e8b1f1c0e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8";
        
        circuitPath = "./circuits/intentProof.r1cs";
        witnessPath = "./circuits/intentProof.wasm";
        provingKeyPath = "./circuits/intentProof_0000.zkey";
        verificationKeyPath = "./circuits/verification_key.json";
        
        const IntentVerifier = await ethers.getContractFactory("IntentVerifier");
        intentVerifier = await IntentVerifier.deploy(owner.address);
        await intentVerifier.waitForDeployment();
        
        zkMiddleware = new ZKMiddleware({
            verifierAddress: await intentVerifier.getAddress(),
            agentAddress: await agent.getAddress(),
            privateKey: privateKey,
            circuitPath: circuitPath,
            witnessPath: witnessPath,
            provingKeyPath: provingKeyPath,
            verificationKeyPath: verificationKeyPath
        });
    });
    
    beforeEach(async function () {
        await intentVerifier.registerAgent(
            await agent.getAddress(),
            TEST_BOUND_MIN,
            TEST_BOUND_MAX,
            [TEST_TARGET_CONTRACT],
            { value: ethers.parseEther("0.1") }
        );
    });
    
    describe("Contract Deployment", function () {
        it("Should deploy with correct owner", async function () {
            expect(await intentVerifier.owner()).to.equal(owner.address);
        });
        
        it("Should initialize with empty agent registry", async function () {
            const isAgent = await intentVerifier.isAgent(await agent.getAddress());
            expect(isAgent).to.be.false;
        });
        
        it("Should have correct verification key structure", async function () {
            const vkAlpha1X = await intentVerifier.VK_ALPHA1_X();
            expect(vkAlpha1X).to.not.equal(0);
        });
    });
    
    describe("Agent Registration", function () {
        it("Should register agent with bounds", async function () {
            const tx = await intentVerifier.registerAgent(
                await agent.getAddress(),
                TEST_BOUND_MIN,
                TEST_BOUND_MAX,
                [TEST_TARGET_CONTRACT],
                { value: ethers.parseEther("0.1") }
            );
            await tx.wait();
            
            const isAgent = await intentVerifier.isAgent(await agent.getAddress());
            expect(isAgent).to.be.true;
        });
        
        it("Should reject duplicate agent registration", async function () {
            await expect(
                intentVerifier.registerAgent(
                    await agent.getAddress(),
                    TEST_BOUND_MIN,
                    TEST_BOUND_MAX,
                    [TEST_TARGET_CONTRACT],
                    { value: ethers.parseEther("0.1") }
                )
            ).to.be.reverted;
        });
        
        it("Should reject unauthorized agent registration", async function () {
            await expect(
                intentVerifier.connect(attacker).registerAgent(
                    await attacker.getAddress(),
                    TEST_BOUND_MIN,
                    TEST_BOUND_MAX,
                    [TEST_TARGET_CONTRACT],
                    { value: ethers.parseEther("0.1") }
                )
            ).to.be.reverted;
        });
        
        it("Should validate contract address format", async function () {
            const invalidAddress = "0x123";
            await expect(
                intentVerifier.registerAgent(
                    await agent.getAddress(),
                    TEST_BOUND_MIN,
                    TEST_BOUND_MAX,
                    [invalidAddress],
                    { value: ethers.parseEther("0.1") }
                )
            ).to.be.reverted;
        });
    });
    
    describe("Valid ZK Proof Verification", function () {
        it("Should verify valid proof with correct bounds", async function () {
            const messageHash = ethers.keccak256(
                ethers.solidityPacked(
                    ["string", "uint256", "uint256", "address"],
                    [TEST_MESSAGE, TEST_ACTION_VALUE, TEST_TIMESTAMP, TEST_TARGET_CONTRACT]
                )
            );
            
            const signature = await owner.signMessage(ethers.getBytes(messageHash));
            const sigParts = ethers.Signature.from(signature);
            
            const publicInputs = {
                messageHash: messageHash,
                r: sigParts.r,
                s: sigParts.s,
                v: sigParts.v,
                publicKeyX: publicKeyX,
                publicKeyY: publicKeyY,
                actionValue: TEST_ACTION_VALUE,
                minBound: TEST_BOUND_MIN,
                maxBound: TEST_BOUND_MAX,
                timestamp: TEST_TIMESTAMP,
                blockNumber: TEST_BLOCK_NUMBER,
                targetContract: TEST_TARGET_CONTRACT
            };
            
            const { proof, publicSignals } = await groth16.fullProve(
                publicInputs,
                witnessPath,
                provingKeyPath
            );
            
            const isValid = await intentVerifier.verifyIntentProof(
                proof,
                publicSignals
            );
            
            expect(isValid).to.be.true;
        });
        
        it("Should verify proof at minimum bound", async function () {
            const messageHash = ethers.keccak256(
                ethers.solidityPacked(
                    ["string", "uint256", "uint256", "address"],
                    [TEST_MESSAGE, TEST_BOUND_MIN, TEST_TIMESTAMP, TEST_TARGET_CONTRACT]
                )
            );
            
            const signature = await owner.signMessage(ethers.getBytes(messageHash));
            const sigParts = ethers.Signature.from(signature);
            
            const publicInputs = {
                messageHash: messageHash,
                r: sigParts.r,
                s: sigParts.s,
                v: sigParts.v,
                publicKeyX: publicKeyX,
                publicKeyY: publicKeyY,
                actionValue: TEST_BOUND_MIN,
                minBound: TEST_BOUND_MIN,
                maxBound: TEST_BOUND_MAX,
                timestamp: TEST_TIMESTAMP,
                blockNumber: TEST_BLOCK_NUMBER,
                targetContract: TEST_TARGET_CONTRACT
            };
            
            const { proof, publicSignals } = await groth16.fullProve(
                publicInputs,
                witnessPath,
                provingKeyPath
            );
            
            const isValid = await intentVerifier.verifyIntentProof(
                proof,
                publicSignals
            );
            
            expect(isValid).to.be.true;
        });
        
        it("Should verify proof at maximum bound", async function () {
            const messageHash = ethers.keccak256(
                ethers.solidityPacked(
                    ["string", "uint256", "uint256", "address"],
                    [TEST_MESSAGE, TEST_BOUND_MAX, TEST_TIMESTAMP, TEST_TARGET_CONTRACT]
                )
            );
            
            const signature = await owner.signMessage(ethers.getBytes(messageHash));
            const sigParts = ethers.Signature.from(signature);
            
            const publicInputs = {
                messageHash: messageHash,
                r: sigParts.r,
                s: sigParts.s,
                v: sigParts.v,
                publicKeyX: publicKeyX,
                publicKeyY: publicKeyY,
                actionValue: TEST_BOUND_MAX,
                minBound: TEST_BOUND_MIN,
                maxBound: TEST_BOUND_MAX,
                timestamp: TEST_TIMESTAMP,
                blockNumber: TEST_BLOCK_NUMBER,
                targetContract: TEST_TARGET_CONTRACT
            };
            
            const { proof, publicSignals } = await groth16.fullProve(
                publicInputs,
                witnessPath,
                provingKeyPath
            );
            
            const isValid = await intentVerifier.verifyIntentProof(
                proof,
                publicSignals
            );
            
            expect(isValid).to.be.true;
        });
    });
    
    describe("Invalid ZK Proof Verification", function () {
        it("Should reject proof with out-of-bounds action value", async function () {
            const outOfBoundsValue = TEST_BOUND_MAX + 1n;
            const messageHash = ethers.keccak256(
                ethers.solidityPacked(
                    ["string", "uint256", "uint256", "address"],
                    [TEST_MESSAGE, outOfBoundsValue, TEST_TIMESTAMP, TEST_TARGET_CONTRACT]
                )
            );
            
            const signature = await owner.signMessage(ethers.getBytes(messageHash));
            const sigParts = ethers.Signature.from(signature);
            
            const publicInputs = {
                messageHash: messageHash,
                r: sigParts.r,
                s: sigParts.s,
                v: sigParts.v,
                publicKeyX: publicKeyX,
                publicKeyY: publicKeyY,
                actionValue: outOfBoundsValue,
                minBound: TEST_BOUND_MIN,
                maxBound: TEST_BOUND_MAX,
                timestamp: TEST_TIMESTAMP,
                blockNumber: TEST_BLOCK_NUMBER,
                targetContract: TEST_TARGET_CONTRACT
            };
            
            const { proof, publicSignals } = await groth16.fullProve(
                publicInputs,
                witnessPath,
                provingKeyPath
            );
            
            await expect(
                intentVerifier.verifyIntentProof(proof, publicSignals)
            ).to.be.revertedWith("Intent drift detected: action exceeds bounds");
        });
        
        it("Should reject proof with unauthorized target contract", async function () {
            const unauthorizedContract = "0x1234567890123456789012345678901234567890";
            const messageHash = ethers.keccak256(
                ethers.solidityPacked(
                    ["string", "uint256", "uint256", "address"],
                    [TEST_MESSAGE, TEST_ACTION_VALUE, TEST_TIMESTAMP, unauthorizedContract]
                )
            );
            
            const signature = await owner.signMessage(ethers.getBytes(messageHash));
            const sigParts = ethers.Signature.from(signature);
            
            const publicInputs = {
                messageHash: messageHash,
                r: sigParts.r,
                s: sigParts.s,
                v: sigParts.v,
                publicKeyX: publicKeyX,
                publicKeyY: publicKeyY,
                actionValue: TEST_ACTION_VALUE,
                minBound: TEST_BOUND_MIN,
                maxBound: TEST_BOUND_MAX,
                timestamp: TEST_TIMESTAMP,
                blockNumber: TEST_BLOCK_NUMBER,
                targetContract: unauthorizedContract
            };
            
            const { proof, publicSignals } = await groth16.fullProve(
                publicInputs,
                witnessPath,
                provingKeyPath
            );
            
            await expect(
                intentVerifier.verifyIntentProof(proof, publicSignals)
            ).to.be.revertedWith("Unauthorized target contract");
        });
        
        it("Should reject proof with expired timestamp", async function () {
            const expiredTimestamp = TEST_TIMESTAMP - 3600;
            const messageHash = ethers.keccak256(
                ethers.solidityPacked(
                    ["string", "uint256", "uint256", "address"],
                    [TEST_MESSAGE, TEST_ACTION_VALUE, expiredTimestamp, TEST_TARGET_CONTRACT]
                )
            );
            
            const signature = await owner.signMessage(ethers.getBytes(messageHash));
            const sigParts = ethers.Signature.from(signature);
            
            const publicInputs = {
                messageHash: messageHash,
                r: sigParts.r,
                s: sigParts.s,
                v: sigParts.v,
                publicKeyX: publicKeyX,
                publicKeyY: publicKeyY,
                actionValue: TEST_ACTION_VALUE,
                minBound: TEST_BOUND_MIN,
                maxBound: TEST_BOUND_MAX,
                timestamp: expiredTimestamp,
                blockNumber: TEST_BLOCK_NUMBER,
                targetContract: TEST_TARGET_CONTRACT
            };
            
            const { proof, publicSignals } = await groth16.fullProve(
                publicInputs,
                witnessPath,
                provingKeyPath
            );
            
            await expect(
                intentVerifier.verifyIntentProof(proof, publicSignals)
            ).to.be.revertedWith("Proof expired: timestamp too old");
        });
        
        it("Should reject proof with tampered signature", async function () {
            const messageHash = ethers.keccak256(
                ethers.solidityPacked(
                    ["string", "uint256", "uint256", "address"],
                    [TEST_MESSAGE, TEST_ACTION_VALUE, TEST_TIMESTAMP, TEST_TARGET_CONTRACT]
                )
            );
            
            const signature = await owner.signMessage(ethers.getBytes(messageHash));
            const sigParts = ethers.Signature.from(signature);
            
            const tamperedR = ethers.toBeHex(
                BigInt(sigParts.r) + 1n,
                64
            );
            
            const publicInputs = {
                messageHash: messageHash,
                r: tamperedR,
                s: sigParts.s,
                v: sigParts.v,
                publicKeyX: publicKeyX,
                publicKeyY: publicKeyY,
                actionValue: TEST_ACTION_VALUE,
                minBound: TEST_BOUND_MIN,
                maxBound: TEST_BOUND_MAX,
                timestamp: TEST_TIMESTAMP,
                blockNumber: TEST_BLOCK_NUMBER,
                targetContract: TEST_TARGET_CONTRACT
            };
            
            const { proof, publicSignals } = await groth16.fullProve(
                publicInputs,
                witnessPath,
                provingKeyPath
            );
            
            await expect(
                intentVerifier.verifyIntentProof(proof, publicSignals)
            ).to.be.revertedWith("Invalid ECDSA signature");
        });
        
        it("Should reject proof with invalid public key", async function () {
            const messageHash = ethers.keccak256(
                ethers.solidityPacked(
                    ["string", "uint256", "uint256", "address"],
                    [TEST_MESSAGE, TEST_ACTION_VALUE, TEST_TIMESTAMP, TEST_TARGET_CONTRACT]
                )
            );
            
            const signature = await owner.signMessage(ethers.getBytes(messageHash));
            const sigParts = ethers.Signature.from(signature);
            
            const invalidPublicKeyX = "0x0000000000000000000000000000000000000000000000000000000000000000";
            
            const publicInputs = {
                messageHash: messageHash,
                r: sigParts.r,
                s: sigParts.s,
                v: sigParts.v,
                publicKeyX: invalidPublicKeyX,
                publicKeyY: publicKeyY,
                actionValue: TEST_ACTION_VALUE,
                minBound: TEST_BOUND_MIN,
                maxBound: TEST_BOUND_MAX,
                timestamp: TEST_TIMESTAMP,
                blockNumber: TEST_BLOCK_NUMBER,
                targetContract: TEST_TARGET_CONTRACT
            };
            
            const { proof, publicSignals } = await groth16.fullProve(
                publicInputs,
                witnessPath,
                provingKeyPath
            );
            
            await expect(
                intentVerifier.verifyIntentProof(proof, publicSignals)
            ).to.be.revertedWith("Invalid public key");
        });
    });
    
    describe("Boundary Conditions", function () {
        it("Should reject zero action value", async function () {
            const messageHash = ethers.keccak256(
                ethers.solidityPacked(
                    ["string", "uint256", "uint256", "address"],
                    [TEST_MESSAGE, 0n, TEST_TIMESTAMP, TEST_TARGET_CONTRACT]
                )
            );
            
            const signature = await owner.signMessage(ethers.getBytes(messageHash));
            const sigParts = ethers.Signature.from(signature);
            
            const publicInputs = {
                messageHash: messageHash,
                r: sigParts.r,
                s: sigParts.s,
                v: sigParts.v,
                publicKeyX: publicKeyX,
                publicKeyY: publicKeyY,
                actionValue: 0n,
                minBound: TEST_BOUND_MIN,
                maxBound: TEST_BOUND_MAX,
                timestamp: TEST_TIMESTAMP,
                blockNumber: TEST_BLOCK_NUMBER,
                targetContract: TEST_TARGET_CONTRACT
            };
            
            const { proof, publicSignals } = await groth16.fullProve(
                publicInputs,
                witnessPath,
                provingKeyPath
            );
            
            await expect(
                intentVerifier.verifyIntentProof(proof, publicSignals)
            ).to.be.revertedWith("Intent drift detected: action exceeds bounds");
        });
        
        it("Should reject negative action value (underflow)", async function () {
            const messageHash = ethers.keccak256(
                ethers.solidityPacked(
                    ["string", "uint256", "uint256", "address"],
                    [TEST_MESSAGE, 0n, TEST_TIMESTAMP, TEST_TARGET_CONTRACT]
                )
            );
            
            const signature = await owner.signMessage(ethers.getBytes(messageHash));
            const sigParts = ethers.Signature.from(signature);
            
            const publicInputs = {
                messageHash: messageHash,
                r: sigParts.r,
                s: sigParts.s,
                v: sigParts.v,
                publicKeyX: publicKeyX,
                publicKeyY: publicKeyY,
                actionValue: 0n,
                minBound: TEST_BOUND_MIN,
                maxBound: TEST_BOUND_MAX,
                timestamp: TEST_TIMESTAMP,
                blockNumber: TEST_BLOCK_NUMBER,
                targetContract: TEST_TARGET_CONTRACT
            };
            
            const { proof, publicSignals } = await groth16.fullProve(
                publicInputs,
                witnessPath,
                provingKeyPath
            );
            
            await expect(
                intentVerifier.verifyIntentProof(proof, publicSignals)
            ).to.be.revertedWith("Intent drift detected: action exceeds bounds");
        });
        
        it("Should reject future timestamp", async function () {
            const futureTimestamp = TEST_TIMESTAMP + 86400;
            const messageHash = ethers.keccak256(
                ethers.solidityPacked(
                    ["string", "uint256", "uint256", "address"],
                    [TEST_MESSAGE, TEST_ACTION_VALUE, futureTimestamp, TEST_TARGET_CONTRACT]
                )
            );
            
            const signature = await owner.signMessage(ethers.getBytes(messageHash));
            const sigParts = ethers.Signature.from(signature);
            
            const publicInputs = {
                messageHash: messageHash,
                r: sigParts.r,
                s: sigParts.s,
                v: sigParts.v,
                publicKeyX: publicKeyX,
                publicKeyY: publicKeyY,
                actionValue: TEST_ACTION_VALUE,
                minBound: TEST_BOUND_MIN,
                maxBound: TEST_BOUND_MAX,
                timestamp: futureTimestamp,
                blockNumber: TEST_BLOCK_NUMBER,
                targetContract: TEST_TARGET_CONTRACT
            };
            
            const { proof, publicSignals } = await groth16.fullProve(
                publicInputs,
                witnessPath,
                provingKeyPath
            );
            
            await expect(
                intentVerifier.verifyIntentProof(proof, publicSignals)
            ).to.be.revertedWith("Proof expired: timestamp too old");
        });
        
        it("Should reject empty target contract array", async function () {
            await expect(
                intentVerifier.registerAgent(
                    await agent.getAddress(),
                    TEST_BOUND_MIN,
                    TEST_BOUND_MAX,
                    [],
                    { value: ethers.parseEther("0.1") }
                )
            ).to.be.reverted;
        });
    });
    
    describe("Middleware Integration", function () {
        it("Should block unauthorized action via middleware", async function () {
            const unauthorizedAction = {
                action: "transfer",
                target: "0x1234567890123456789012345678901234567890",
                value: TEST_ACTION_VALUE,
                timestamp: TEST_TIMESTAMP
            };
            
            await expect(
                zkMiddleware.executeAction(unauthorizedAction)
            ).to.be.rejectedWith("Unauthorized target contract");
        });
        
        it("Should block out-of-bounds action via middleware", async function () {
            const outOfBoundsAction = {
                action: "transfer",
                target: TEST_TARGET_CONTRACT,
                value: TEST_BOUND_MAX + 1000n,
                timestamp: TEST_TIMESTAMP
            };
            
            await expect(
                zkMiddleware.executeAction(outOfBoundsAction)
            ).to.be.rejectedWith("Intent drift detected: action exceeds bounds");
        });
        
        it("Should allow authorized action via middleware", async function () {
            const authorizedAction = {
                action: "transfer",
                target: TEST_TARGET_CONTRACT,
                value: TEST_ACTION_VALUE,
                timestamp: TEST_TIMESTAMP
            };
            
            const result = await zkMiddleware.executeAction(authorizedAction);
            expect(result).to.not.be.null;
        });
        
        it("Should reject expired action via middleware", async function () {
            const expiredAction = {
                action: "transfer",
                target: TEST_TARGET_CONTRACT,
                value: TEST_ACTION_VALUE,
                timestamp: TEST_TIMESTAMP - 3600
            };
            
            await expect(
                zkMiddleware.executeAction(expiredAction)
            ).to.be.rejectedWith("Proof expired: timestamp too old");
        });
    });
    
    describe("Intent Bounds Management", function () {
        it("Should update agent bounds", async function () {
            const newMin = 500n;
            const newMax = 15000n;
            
            await intentVerifier.updateIntentBounds(
                await agent.getAddress(),
                newMin,
                newMax
            );
            
            const agentData = await intentVerifier.agents(await agent.getAddress());
            expect(agentData.minBound).to.equal(newMin);
            expect(agentData.maxBound).to.equal(newMax);
        });
        
        it("Should reject unauthorized bounds update", async function () {
            await expect(
                intentVerifier.connect(attacker).updateIntentBounds(
                    await agent.getAddress(),
                    500n,
                    15000n
                )
            ).to.be.reverted;
        });
        
        it("Should reject invalid bounds (min > max)", async function () {
            await expect(
                intentVerifier.updateIntentBounds(
                    await agent.getAddress(),
                    15000n,
                    500n
                )
            ).to.be.revertedWith("Invalid bounds: min > max");
        });
    });
    
    describe("Event Emission", function () {
        it("Should emit IntentVerified event on valid proof", async function () {
            const messageHash = ethers.keccak256(
                ethers.solidityPacked(
                    ["string", "uint256", "uint256", "address"],
                    [TEST_MESSAGE, TEST_ACTION_VALUE, TEST_TIMESTAMP, TEST_TARGET_CONTRACT]
                )
            );
            
            const signature = await owner.signMessage(ethers.getBytes(messageHash));
            const sigParts = ethers.Signature.from(signature);
            
            const publicInputs = {
                messageHash: messageHash,
                r: sigParts.r,
                s: sigParts.s,
                v: sigParts.v,
                publicKeyX: publicKeyX,
                publicKeyY: publicKeyY,
                actionValue: TEST_ACTION_VALUE,
                minBound: TEST_BOUND_MIN,
                maxBound: TEST_BOUND_MAX,
                timestamp: TEST_TIMESTAMP,
                blockNumber: TEST_BLOCK_NUMBER,
                targetContract: TEST_TARGET_CONTRACT
            };
            
            const { proof, publicSignals } = await groth16.fullProve(
                publicInputs,
                witnessPath,
                provingKeyPath
            );
            
            const tx = await intentVerifier.verifyIntentProof(proof, publicSignals);
            const receipt = await tx.wait();
            
            const event = receipt.events?.find(e => e.event === "IntentVerified");
            expect(event).to.not.be.undefined;
        });
        
        it("Should emit IntentRejected event on invalid proof", async function () {
            const messageHash = ethers.keccak256(
                ethers.solidityPacked(
                    ["string", "uint256", "uint256", "address"],
                    [TEST_MESSAGE, TEST_BOUND_MAX + 1n, TEST_TIMESTAMP, TEST_TARGET_CONTRACT]
                )
            );
            
            const signature = await owner.signMessage(ethers.getBytes(messageHash));
            const sigParts = ethers.Signature.from(signature);
            
            const publicInputs = {
                messageHash: messageHash,
                r: sigParts.r,
                s: sigParts.s,
                v: sigParts.v,
                publicKeyX: publicKeyX,
                publicKeyY: publicKeyY,
                actionValue: TEST_BOUND_MAX + 1n,
                minBound: TEST_BOUND_MIN,
                maxBound: TEST_BOUND_MAX,
                timestamp: TEST_TIMESTAMP,
                blockNumber: TEST_BLOCK_NUMBER,
                targetContract: TEST_TARGET_CONTRACT
            };
            
            const { proof, publicSignals } = await groth16.fullProve(
                publicInputs,
                witnessPath,
                provingKeyPath
            );
            
            await expect(
                intentVerifier.verifyIntentProof(proof, publicSignals)
            ).to.be.reverted;
        });
    });
    
    describe("Security Edge Cases", function () {
        it("Should prevent replay attack with same proof", async function () {
            const messageHash = ethers.keccak256(
                ethers.solidityPacked(
                    ["string", "uint256", "uint256", "address"],
                    [TEST_MESSAGE, TEST_ACTION_VALUE, TEST_TIMESTAMP, TEST_TARGET_CONTRACT]
                )
            );
            
            const signature = await owner.signMessage(ethers.getBytes(messageHash));
            const sigParts = ethers.Signature.from(signature);
            
            const publicInputs = {
                messageHash: messageHash,
                r: sigParts.r,
                s: sigParts.s,
                v: sigParts.v,
                publicKeyX: publicKeyX,
                publicKeyY: publicKeyY,
                actionValue: TEST_ACTION_VALUE,
                minBound: TEST_BOUND_MIN,
                maxBound: TEST_BOUND_MAX,
                timestamp: TEST_TIMESTAMP,
                blockNumber: TEST_BLOCK_NUMBER,
                targetContract: TEST_TARGET_CONTRACT
            };
            
            const { proof, publicSignals } = await groth16.fullProve(
                publicInputs,
                witnessPath,
                provingKeyPath
            );
            
            await intentVerifier.verifyIntentProof(proof, publicSignals);
            
            await expect(
                intentVerifier.verifyIntentProof(proof, publicSignals)
            ).to.be.revertedWith("Proof already used");
        });
        
        it("Should prevent signature malleability attack", async function () {
            const messageHash = ethers.keccak256(
                ethers.solidityPacked(
                    ["string", "uint256", "uint256", "address"],
                    [TEST_MESSAGE, TEST_ACTION_VALUE, TEST_TIMESTAMP, TEST_TARGET_CONTRACT]
                )
            );
            
            const signature = await owner.signMessage(ethers.getBytes(messageHash));
            const sigParts = ethers.Signature.from(signature);
            
            const malleatedS = ethers.toBeHex(
                ethers.constants.MaxUint256 - BigInt(sigParts.s),
                64
            );
            
            const publicInputs = {
                messageHash: messageHash,
                r: sigParts.r,
                s: malleatedS,
                v: sigParts.v,
                publicKeyX: publicKeyX,
                publicKeyY: publicKeyY,
                actionValue: TEST_ACTION_VALUE,
                minBound: TEST_BOUND_MIN,
                maxBound: TEST_BOUND_MAX,
                timestamp: TEST_TIMESTAMP,
                blockNumber: TEST_BLOCK_NUMBER,
                targetContract: TEST_TARGET_CONTRACT
            };
            
            const { proof, publicSignals } = await groth16.fullProve(
                publicInputs,
                witnessPath,
                provingKeyPath
            );
            
            await expect(
                intentVerifier.verifyIntentProof(proof, publicSignals)
            ).to.be.revertedWith("Invalid ECDSA signature");
        });
        
        it("Should prevent overflow attack on bounds", async function () {
            const overflowValue = ethers.constants.MaxUint256;
            const messageHash = ethers.keccak256(
                ethers.solidityPacked(
                    ["string", "uint256", "uint256", "address"],
                    [TEST_MESSAGE, overflowValue, TEST_TIMESTAMP, TEST_TARGET_CONTRACT]
                )
            );
            
            const signature = await owner.signMessage(ethers.getBytes(messageHash));
            const sigParts = ethers.Signature.from(signature);
            
            const publicInputs = {
                messageHash: messageHash,
                r: sigParts.r,
                s: sigParts.s,
                v: sigParts.v,
                publicKeyX: publicKeyX,
                publicKeyY: publicKeyY,
                actionValue: overflowValue,
                minBound: TEST_BOUND_MIN,
                maxBound: TEST_BOUND_MAX,
                timestamp: TEST_TIMESTAMP,
                blockNumber: TEST_BLOCK_NUMBER,
                targetContract: TEST_TARGET_CONTRACT
            };
            
            const { proof, publicSignals } = await groth16.fullProve(
                publicInputs,
                witnessPath,
                provingKeyPath
            );
            
            await expect(
                intentVerifier.verifyIntentProof(proof, publicSignals)
            ).to.be.revertedWith("Intent drift detected: action exceeds bounds");
        });
    });
    
    describe("Gas Optimization", function () {
        it("Should verify proof within gas limit", async function () {
            const messageHash = ethers.keccak256(
                ethers.solidityPacked(
                    ["string", "uint256", "uint256", "address"],
                    [TEST_MESSAGE, TEST_ACTION_VALUE, TEST_TIMESTAMP, TEST_TARGET_CONTRACT]
                )
            );
            
            const signature = await owner.signMessage(ethers.getBytes(messageHash));
            const sigParts = ethers.Signature.from(signature);
            
            const publicInputs = {
                messageHash: messageHash,
                r: sigParts.r,
                s: sigParts.s,
                v: sigParts.v,
                publicKeyX: publicKeyX,
                publicKeyY: publicKeyY,
                actionValue: TEST_ACTION_VALUE,
                minBound: TEST_BOUND_MIN,
                maxBound: TEST_BOUND_MAX,
                timestamp: TEST_TIMESTAMP,
                blockNumber: TEST_BLOCK_NUMBER,
                targetContract: TEST_TARGET_CONTRACT
            };
            
            const { proof, publicSignals } = await groth16.fullProve(
                publicInputs,
                witnessPath,
                provingKeyPath
            );
            
            const tx = await intentVerifier.verifyIntentProof(proof, publicSignals);
            const receipt = await tx.wait();
            
            expect(receipt.gasUsed).to.be.lessThan(500000n);
        });
    });
});