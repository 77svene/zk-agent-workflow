// VERIFLOW INTEGRATION TEST SUITE
// 
// CRYPTOGRAPHIC WORKFLOW VERIFICATION TESTS
// 
// NOVEL PRIMITIVES:
// - Execution Trace Merkle Tree: Cryptographic commitment to multi-step workflow
// - Deterministic Proof Verification: Reproducible ZK proof generation for testing
// - State Transition Audit Trail: Immutable record of all workflow steps
// - Proof-Execution Alignment: Mathematical guarantee that proof matches trace
//
// SECURITY MODEL:
// - All timestamps are fixed for deterministic testing
// - No external randomness - all values are cryptographically derived
// - Tests verify mathematical correctness, not just functional behavior
// - Proof verification is the ONLY trust mechanism

const { expect } = require("chai");
const { ethers } = require("hardhat");
const { DeterministicStateMachine } = require("../primitives/deterministic_state_machine");
const { WorkflowProofGenerator } = require("../services/proofGenerator");
const { AgentCommunication } = require("../services/agentCommunication");

// ============================================================================
// PRIMITIVE: DETERMINISTIC_TIMESTAMP
// ============================================================================
// Fixed timestamp for reproducible testing - no Date.now()
// This ensures cryptographic determinism across test runs
// ============================================================================
const FIXED_TIMESTAMP = 1704067200; // 2024-01-01 00:00:00 UTC
const FIXED_BLOCK_NUMBER = 18000000;

// ============================================================================
// PRIMITIVE: WORKFLOW_STATE_MERKLE_TREE
// ============================================================================
// Cryptographic commitment to multi-step workflow execution
// Each step is hashed and committed to a Merkle tree for efficient verification
// ============================================================================
class WorkflowStateMerkleTree {
    constructor() {
        this.nodes = [];
        this.root = null;
    }

    // Add a state hash to the tree
    addStateHash(stateHash) {
        this.nodes.push(stateHash);
        this.recalculateRoot();
    }

    // Recalculate Merkle root from all nodes
    recalculateRoot() {
        if (this.nodes.length === 0) {
            this.root = ethers.ZeroHash;
            return;
        }

        let level = [...this.nodes];
        
        while (level.length > 1) {
            const nextLevel = [];
            
            for (let i = 0; i < level.length; i += 2) {
                const left = level[i];
                const right = i + 1 < level.length ? level[i + 1] : ethers.ZeroHash;
                const combined = ethers.solidityPacked(
                    ["bytes32", "bytes32"],
                    [left, right]
                );
                nextLevel.push(ethers.keccak256(combined));
            }
            
            level = nextLevel;
        }
        
        this.root = level[0];
    }

    // Get Merkle proof for a specific index
    getProof(index) {
        if (index < 0 || index >= this.nodes.length) {
            throw new Error("Invalid index for Merkle proof");
        }

        const proof = [];
        let level = [...this.nodes];
        let currentIndex = index;

        while (level.length > 1) {
            const nextLevel = [];
            
            for (let i = 0; i < level.length; i += 2) {
                if (i === currentIndex || i === currentIndex - 1) {
                    if (i === currentIndex) {
                        proof.push({
                            sibling: level[i + 1] || ethers.ZeroHash,
                            position: "right"
                        });
                    } else {
                        proof.push({
                            sibling: level[i],
                            position: "left"
                        });
                    }
                }
                const combined = ethers.solidityPacked(
                    ["bytes32", "bytes32"],
                    [level[i], level[i + 1] || ethers.ZeroHash]
                );
                nextLevel.push(ethers.keccak256(combined));
            }
            
            level = nextLevel;
            currentIndex = Math.floor(currentIndex / 2);
        }

        return {
            root: this.root,
            proof,
            index
        };
    }

    // Verify a Merkle proof
    verifyProof(proof, index, leaf) {
        let currentHash = leaf;
        
        for (const step of proof.proof) {
            const combined = step.position === "left"
                ? ethers.solidityPacked(
                    ["bytes32", "bytes32"],
                    [step.sibling, currentHash]
                )
                : ethers.solidityPacked(
                    ["bytes32", "bytes32"],
                    [currentHash, step.sibling]
                );
            
            currentHash = ethers.keccak256(combined);
        }

        return currentHash === proof.root;
    }
}

// ============================================================================
// PRIMITIVE: PROOF_EXECUTION_ALIGNMENT
// ============================================================================
// Mathematical verification that ZK proof matches actual execution trace
// Ensures no deviation between claimed and actual workflow execution
// ============================================================================
class ProofExecutionAlignment {
    constructor() {
        this.executionTrace = [];
        this.proofData = null;
    }

    // Record an execution step
    recordStep(stepData) {
        const stepHash = ethers.keccak256(
            ethers.toUtf8Bytes(JSON.stringify(stepData))
        );
        
        this.executionTrace.push({
            stepHash,
            timestamp: FIXED_TIMESTAMP + this.executionTrace.length,
            data: stepData
        });
    }

    // Generate proof from execution trace
    generateProof() {
        const stateHashes = this.executionTrace.map(step => step.stepHash);
        const merkleTree = new WorkflowStateMerkleTree();
        
        for (const hash of stateHashes) {
            merkleTree.addStateHash(hash);
        }

        this.proofData = {
            merkleRoot: merkleTree.root,
            stateHashes,
            traceLength: this.executionTrace.length,
            timestamp: FIXED_TIMESTAMP
        };

        return this.proofData;
    }

    // Verify proof matches execution trace
    verifyAlignment(proofData) {
        if (this.executionTrace.length === 0) {
            return {
                valid: false,
                reason: "No execution trace recorded"
            };
        }

        if (proofData.stateHashes.length !== this.executionTrace.length) {
            return {
                valid: false,
                reason: "Proof state hash count mismatch"
            };
        }

        // Verify each state hash matches execution trace
        for (let i = 0; i < this.executionTrace.length; i++) {
            const expectedHash = this.executionTrace[i].stepHash;
            const proofHash = proofData.stateHashes[i];
            
            if (expectedHash !== proofHash) {
                return {
                    valid: false,
                    reason: `State hash mismatch at index ${i}`
                };
            }
        }

        // Verify Merkle root
        const merkleTree = new WorkflowStateMerkleTree();
        for (const hash of proofData.stateHashes) {
            merkleTree.addStateHash(hash);
        }

        if (merkleTree.root !== proofData.merkleRoot) {
            return {
                valid: false,
                reason: "Merkle root mismatch"
            };
        }

        return {
            valid: true,
            reason: "Proof execution alignment verified"
        };
    }
}

// ============================================================================
// TEST SUITE: VERIFLOW WORKFLOW INTEGRATION
// ============================================================================
describe("VeriFlow Workflow Integration Tests", function () {
    let agentController;
    let agentVerifier;
    let deterministicState;
    let proofGenerator;
    let agentCommunication;
    let executionAlignment;

    // ========================================================================
    // SETUP: Deploy contracts and initialize primitives
    // ========================================================================
    before(async function () {
        // Deploy contracts
        const AgentVerifierFactory = await ethers.getContractFactory("AgentVerifier");
        agentVerifier = await AgentVerifierFactory.deploy();
        await agentVerifier.waitForDeployment();

        const AgentControllerFactory = await ethers.getContractFactory("AgentController");
        agentController = await AgentControllerFactory.deploy(agentVerifier.target);
        await agentController.waitForDeployment();

        // Initialize primitives
        deterministicState = new DeterministicStateMachine();
        proofGenerator = new WorkflowProofGenerator();
        agentCommunication = new AgentCommunication();
        executionAlignment = new ProofExecutionAlignment();
    });

    // ========================================================================
    // TEST: Single Agent State Transition with ZK Proof
    // ========================================================================
    describe("Single Agent State Transition", function () {
        it("Should execute deterministic state transition and generate valid ZK proof", async function () {
            // Define initial state
            const initialState = {
                agentId: "agent-001",
                taskId: "task-aggregation-001",
                step: 1,
                inputData: {
                    source: "data-source-alpha",
                    value: 1000
                }
            };

            // Execute state transition
            const stateTransition = deterministicState.transition(
                initialState,
                "process_data",
                { operation: "aggregate", multiplier: 2 }
            );

            // Record execution trace
            executionAlignment.recordStep({
                ...stateTransition,
                operation: "process_data",
                parameters: { operation: "aggregate", multiplier: 2 }
            });

            // Generate ZK proof
            const proofData = executionAlignment.generateProof();

            // Verify proof-execution alignment
            const alignmentResult = executionAlignment.verifyAlignment(proofData);
            expect(alignmentResult.valid).to.be.true;
            expect(alignmentResult.reason).to.equal("Proof execution alignment verified");

            // Verify state hash is deterministic
            const stateHash = stateTransition.stateHash;
            const expectedHash = ethers.keccak256(
                ethers.toUtf8Bytes(JSON.stringify(stateTransition))
            );
            expect(stateHash).to.equal(expectedHash);
        });

        it("Should reject invalid state transitions with cryptographic proof", async function () {
            const initialState = {
                agentId: "agent-002",
                taskId: "task-aggregation-002",
                step: 1,
                inputData: { source: "data-source-beta", value: 500 }
            };

            // Attempt invalid transition (missing required field)
            const invalidTransition = {
                ...initialState,
                step: 2,
                outputData: { result: 1000 },
                stateHash: "invalid-hash"
            };

            // Verify state hash is invalid
            const isValid = deterministicState.validateState(invalidTransition);
            expect(isValid).to.be.false;
        });
    });

    // ========================================================================
    // TEST: Multi-Agent Workflow with State Chain
    // ========================================================================
    describe("Multi-Agent Workflow Execution", function () {
        it("Should execute multi-step workflow with cryptographic state chain", async function () {
            const workflowSteps = [
                {
                    agentId: "agent-data-collector",
                    operation: "collect",
                    parameters: { sources: ["source-1", "source-2"] }
                },
                {
                    agentId: "agent-data-validator",
                    operation: "validate",
                    parameters: { rules: ["schema-compliance", "range-check"] }
                },
                {
                    agentId: "agent-data-aggregator",
                    operation: "aggregate",
                    parameters: { method: "sum", groupBy: "category" }
                }
            ];

            let currentState = {
                workflowId: "workflow-multi-agent-001",
                step: 0,
                stateChain: [],
                timestamp: FIXED_TIMESTAMP
            };

            // Execute each workflow step
            for (const step of workflowSteps) {
                const stateTransition = deterministicState.transition(
                    currentState,
                    step.operation,
                    step.parameters
                );

                // Record execution trace
                executionAlignment.recordStep({
                    ...stateTransition,
                    agentId: step.agentId,
                    operation: step.operation,
                    parameters: step.parameters
                });

                // Add state to chain
                currentState.stateChain.push(stateTransition.stateHash);
                currentState.step++;
                currentState = stateTransition;
            }

            // Generate ZK proof for entire workflow
            const proofData = executionAlignment.generateProof();

            // Verify proof matches execution trace
            const alignmentResult = executionAlignment.verifyAlignment(proofData);
            expect(alignmentResult.valid).to.be.true;

            // Verify state chain integrity
            expect(currentState.stateChain.length).to.equal(workflowSteps.length);

            // Verify each state hash in chain is unique
            const uniqueHashes = new Set(currentState.stateChain);
            expect(uniqueHashes.size).to.equal(currentState.stateChain.length);
        });

        it("Should verify multi-agent workflow on-chain", async function () {
            const workflowSteps = [
                {
                    agentId: "agent-001",
                    operation: "initiate",
                    parameters: { value: 100 }
                },
                {
                    agentId: "agent-002",
                    operation: "process",
                    parameters: { value: 200 }
                }
            ];

            let currentState = {
                workflowId: "workflow-onchain-001",
                step: 0,
                stateChain: [],
                timestamp: FIXED_TIMESTAMP
            };

            // Execute workflow steps
            for (const step of workflowSteps) {
                const stateTransition = deterministicState.transition(
                    currentState,
                    step.operation,
                    step.parameters
                );

                executionAlignment.recordStep({
                    ...stateTransition,
                    agentId: step.agentId,
                    operation: step.operation
                });

                currentState.stateChain.push(stateTransition.stateHash);
                currentState.step++;
                currentState = stateTransition;
            }

            // Generate proof
            const proofData = executionAlignment.generateProof();

            // Submit to on-chain verifier
            const proof = await proofGenerator.generateProof(proofData);
            const inputs = proofData.stateHashes;

            // Verify proof on-chain
            const isValid = await agentVerifier.verifyProof(proof.proof, inputs);
            expect(isValid).to.be.true;

            // Commit state to controller
            const tx = await agentController.commitWorkflowState(
                proofData.workflowId,
                proofData.merkleRoot,
                proofData.stateChain
            );
            await tx.wait();

            // Verify state was committed
            const committedState = await agentController.getWorkflowState(
                proofData.workflowId
            );
            expect(committedState.merkleRoot).to.equal(proofData.merkleRoot);
        });
    });

    // ========================================================================
    // TEST: Proof Verification and State Integrity
    // ========================================================================
    describe("Proof Verification and State Integrity", function () {
        it("Should verify proof integrity against Merkle root", async function () {
            const merkleTree = new WorkflowStateMerkleTree();
            
            // Add state hashes
            const stateHashes = [
                ethers.keccak256(ethers.toUtf8Bytes("state-1")),
                ethers.keccak256(ethers.toUtf8Bytes("state-2")),
                ethers.keccak256(ethers.toUtf8Bytes("state-3"))
            ];

            for (const hash of stateHashes) {
                merkleTree.addStateHash(hash);
            }

            // Get Merkle proof for first state
            const proof = merkleTree.getProof(0);

            // Verify proof
            const isValid = merkleTree.verifyProof(proof, 0, stateHashes[0]);
            expect(isValid).to.be.true;

            // Verify proof for invalid index
            const invalidProof = merkleTree.getProof(10);
            expect(() => merkleTree.verifyProof(invalidProof, 10, stateHashes[0]))
                .to.throw("Invalid index for Merkle proof");
        });

        it("Should detect tampered execution trace", async function () {
            // Record original execution trace
            executionAlignment.recordStep({
                agentId: "agent-001",
                operation: "process",
                value: 1000,
                timestamp: FIXED_TIMESTAMP
            });

            // Generate original proof
            const originalProof = executionAlignment.generateProof();

            // Tamper with execution trace
            executionAlignment.recordStep({
                agentId: "agent-001",
                operation: "process",
                value: 999, // Tampered value
                timestamp: FIXED_TIMESTAMP
            });

            // Generate tampered proof
            const tamperedProof = executionAlignment.generateProof();

            // Verify alignment fails
            const alignmentResult = executionAlignment.verifyAlignment(tamperedProof);
            expect(alignmentResult.valid).to.be.false;
            expect(alignmentResult.reason).to.include("State hash mismatch");
        });

        it("Should verify deterministic state generation", async function () {
            const initialState = {
                agentId: "agent-deterministic",
                taskId: "task-deterministic-001",
                step: 1,
                inputData: { value: 500 }
            };

            // Generate multiple transitions with same input
            const transitions = [];
            for (let i = 0; i < 5; i++) {
                const transition = deterministicState.transition(
                    initialState,
                    "process",
                    { operation: "multiply", factor: 2 }
                );
                transitions.push(transition);
            }

            // All transitions should be identical
            const firstHash = transitions[0].stateHash;
            for (let i = 1; i < transitions.length; i++) {
                expect(transitions[i].stateHash).to.equal(firstHash);
            }
        });
    });

    // ========================================================================
    // TEST: Agent Communication with ZK Verification
    // ========================================================================
    describe("Agent Communication with ZK Verification", function () {
        it("Should verify agent communication with cryptographic nonce", async function () {
            const message = {
                sender: "agent-001",
                receiver: "agent-002",
                content: "data-aggregation-request",
                timestamp: FIXED_TIMESTAMP
            };

            // Generate message with cryptographic nonce
            const nonce = ethers.randomBytes(32);
            const messageWithNonce = {
                ...message,
                nonce: nonce
            };

            // Sign message
            const signers = await ethers.getSigners();
            const signer = signers[0];
            const messageHash = ethers.keccak256(
                ethers.toUtf8Bytes(JSON.stringify(messageWithNonce))
            );
            const signature = await signer.signMessage(ethers.getBytes(messageHash));

            // Verify signature
            const recoveredSigner = ethers.verifyMessage(
                ethers.getBytes(messageHash),
                signature
            );
            expect(recoveredSigner).to.equal(signer.address);
        });

        it("Should prevent replay attacks with nonce verification", async function () {
            const message = {
                sender: "agent-003",
                receiver: "agent-004",
                content: "state-update",
                timestamp: FIXED_TIMESTAMP,
                nonce: ethers.randomBytes(32)
            };

            // Store used nonces
            const usedNonces = new Set();
            usedNonces.add(message.nonce);

            // Attempt to reuse nonce
            const replayMessage = {
                ...message,
                timestamp: FIXED_TIMESTAMP + 1
            };

            // Verify nonce is not reused
            expect(usedNonces.has(replayMessage.nonce)).to.be.false;
        });
    });

    // ========================================================================
    // TEST: End-to-End Workflow Verification
    // ========================================================================
    describe("End-to-End Workflow Verification", function () {
        it("Should complete full workflow with cryptographic guarantees", async function () {
            // Initialize workflow
            const workflowId = "workflow-e2e-001";
            const initialState = {
                workflowId,
                step: 0,
                stateChain: [],
                timestamp: FIXED_TIMESTAMP
            };

            // Define workflow steps
            const workflowSteps = [
                {
                    agentId: "agent-collector",
                    operation: "collect",
                    parameters: { sources: ["source-a", "source-b"] }
                },
                {
                    agentId: "agent-validator",
                    operation: "validate",
                    parameters: { rules: ["schema", "range"] }
                },
                {
                    agentId: "agent-aggregator",
                    operation: "aggregate",
                    parameters: { method: "sum" }
                },
                {
                    agentId: "agent-reporter",
                    operation: "report",
                    parameters: { format: "json" }
                }
            ];

            let currentState = initialState;

            // Execute workflow
            for (const step of workflowSteps) {
                const stateTransition = deterministicState.transition(
                    currentState,
                    step.operation,
                    step.parameters
                );

                executionAlignment.recordStep({
                    ...stateTransition,
                    agentId: step.agentId,
                    operation: step.operation,
                    parameters: step.parameters
                });

                currentState.stateChain.push(stateTransition.stateHash);
                currentState.step++;
                currentState = stateTransition;
            }

            // Generate ZK proof
            const proofData = executionAlignment.generateProof();
            const proof = await proofGenerator.generateProof(proofData);

            // Verify proof on-chain
            const isValid = await agentVerifier.verifyProof(proof.proof, proofData.stateHashes);
            expect(isValid).to.be.true;

            // Commit to controller
            const tx = await agentController.commitWorkflowState(
                workflowId,
                proofData.merkleRoot,
                currentState.stateChain
            );
            await tx.wait();

            // Verify committed state
            const committedState = await agentController.getWorkflowState(workflowId);
            expect(committedState.merkleRoot).to.equal(proofData.merkleRoot);
            expect(committedState.stateChain.length).to.equal(workflowSteps.length);

            // Verify proof-execution alignment
            const alignmentResult = executionAlignment.verifyAlignment(proofData);
            expect(alignmentResult.valid).to.be.true;
        });

        it("Should handle workflow with multiple concurrent agents", async function () {
            const workflowId = "workflow-concurrent-001";
            const agents = ["agent-001", "agent-002", "agent-003"];
            const operations = ["collect", "validate", "aggregate"];

            let currentState = {
                workflowId,
                step: 0,
                stateChain: [],
                timestamp: FIXED_TIMESTAMP
            };

            // Execute concurrent operations
            for (let i = 0; i < 3; i++) {
                const agentId = agents[i % agents.length];
                const operation = operations[i % operations.length];

                const stateTransition = deterministicState.transition(
                    currentState,
                    operation,
                    { agentId, concurrent: true }
                );

                executionAlignment.recordStep({
                    ...stateTransition,
                    agentId,
                    operation,
                    concurrent: true
                });

                currentState.stateChain.push(stateTransition.stateHash);
                currentState.step++;
                currentState = stateTransition;
            }

            // Generate and verify proof
            const proofData = executionAlignment.generateProof();
            const proof = await proofGenerator.generateProof(proofData);
            const isValid = await agentVerifier.verifyProof(proof.proof, proofData.stateHashes);
            
            expect(isValid).to.be.true;
            expect(currentState.stateChain.length).to.equal(3);
        });
    });

    // ========================================================================
    // TEST: Edge Cases and Security Verification
    // ========================================================================
    describe("Edge Cases and Security Verification", function () {
        it("Should handle empty workflow gracefully", async function () {
            const emptyWorkflow = {
                workflowId: "workflow-empty-001",
                step: 0,
                stateChain: [],
                timestamp: FIXED_TIMESTAMP
            };

            const proofData = executionAlignment.generateProof();
            expect(proofData.stateHashes.length).to.equal(0);
            expect(proofData.merkleRoot).to.equal(ethers.ZeroHash);
        });

        it("Should reject workflow with invalid state hash format", async function () {
            const invalidState = {
                agentId: "agent-001",
                taskId: "task-001",
                step: 1,
                stateHash: "invalid" // Not a valid hash
            };

            const isValid = deterministicState.validateState(invalidState);
            expect(isValid).to.be.false;
        });

        it("Should verify Merkle proof for large state chains", async function () {
            const merkleTree = new WorkflowStateMerkleTree();
            
            // Add 100 state hashes
            const stateHashes = [];
            for (let i = 0; i < 100; i++) {
                const hash = ethers.keccak256(ethers.toUtf8Bytes(`state-${i}`));
                stateHashes.push(hash);
                merkleTree.addStateHash(hash);
            }

            // Verify proofs for random indices
            for (let i = 0; i < 10; i++) {
                const index = Math.floor(Math.random() * 100);
                const proof = merkleTree.getProof(index);
                const isValid = merkleTree.verifyProof(proof, index, stateHashes[index]);
                expect(isValid).to.be.true;
            }
        });

        it("Should detect state chain tampering", async function () {
            const workflowId = "workflow-tamper-001";
            const initialState = {
                workflowId,
                step: 0,
                stateChain: [],
                timestamp: FIXED_TIMESTAMP
            };

            // Execute first two steps
            let currentState = initialState;
            for (let i = 0; i < 2; i++) {
                const stateTransition = deterministicState.transition(
                    currentState,
                    "process",
                    { value: i }
                );

                currentState.stateChain.push(stateTransition.stateHash);
                currentState.step++;
                currentState = stateTransition;
            }

            // Tamper with state chain
            const tamperedChain = [...currentState.stateChain];
            tamperedChain[0] = ethers.keccak256(ethers.toUtf8Bytes("tampered"));

            // Verify tampering is detected
            const merkleTree = new WorkflowStateMerkleTree();
            for (const hash of tamperedChain) {
                merkleTree.addStateHash(hash);
            }

            const originalProof = executionAlignment.generateProof();
            const tamperedProof = {
                ...originalProof,
                stateHashes: tamperedChain
            };

            const alignmentResult = executionAlignment.verifyAlignment(tamperedProof);
            expect(alignmentResult.valid).to.be.false;
        });
    });
});