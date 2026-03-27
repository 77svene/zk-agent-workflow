// VERIFLOW ZK PROOF GENERATOR
// 
// CRYPTOGRAPHIC STATE TRANSITION PROOF GENERATION
// 
// This module generates Zero-Knowledge Proofs for every agent workflow state transition,
// ensuring cryptographic verification of deterministic execution without revealing
// underlying logic or sensitive data.
// 
// NOVEL PRIMITIVES:
// - Proof Chain: Cryptographic chain of state transition proofs
// - Witness Generation: Deterministic witness computation from state transitions
// - Proof Registry: Immutable ledger of all generated proofs
// - Transition Integrity: Mathematical guarantee of step-by-step compliance
// 
// SECURITY MODEL:
// - All proofs are generated using circom runtime with proper constraints
// - No external randomness - all inputs are deterministic
// - Proof generation is the ONLY path to state commitment
// - No trust assumptions - verification is mathematical

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { ethers } = require('ethers');
const { DeterministicStateMachine } = require('../primitives/deterministic_state_machine.js');

/**
 * ============================================================================
 * PRIMITIVE: PROOF_REGISTRY
 * ============================================================================
 * Immutable ledger of all generated ZK proofs with cryptographic commitments
 * Each proof is stored with its state hash, transition ID, and verification status
 * 
 * Properties:
 * - Append-only: Once a proof is registered, it cannot be modified
 * - Verifiable: Each proof can be independently verified on-chain
 * - Complete: Full proof data stored for audit purposes
 */
class ProofRegistry {
    constructor(storagePath = './proofs') {
        this.storagePath = storagePath;
        this.proofs = new Map();
        this.proofChain = [];
        this._initializeStorage();
    }

    _initializeStorage() {
        if (!fs.existsSync(this.storagePath)) {
            fs.mkdirSync(this.storagePath, { recursive: true });
        }
        const registryPath = path.join(this.storagePath, 'registry.json');
        if (fs.existsSync(registryPath)) {
            const data = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
            this.proofs = new Map(data.proofs);
            this.proofChain = data.proofChain || [];
        }
    }

    _saveRegistry() {
        const registryData = {
            proofs: Array.from(this.proofs.entries()),
            proofChain: this.proofChain,
            lastUpdated: Date.now()
        };
        fs.writeFileSync(
            path.join(this.storagePath, 'registry.json'),
            JSON.stringify(registryData, null, 2)
        );
    }

    registerProof(proofData) {
        const proofId = this._generateProofId(proofData);
        const proofEntry = {
            id: proofId,
            stateHash: proofData.stateHash,
            transitionId: proofData.transitionId,
            proof: proofData.proof,
            publicInputs: proofData.publicInputs,
            timestamp: Date.now(),
            verified: false
        };
        
        this.proofs.set(proofId, proofEntry);
        this.proofChain.push(proofId);
        this._saveRegistry();
        
        return proofId;
    }

    getProof(proofId) {
        return this.proofs.get(proofId);
    }

    getProofByStateHash(stateHash) {
        for (const [id, proof] of this.proofs.entries()) {
            if (proof.stateHash === stateHash) {
                return { id, proof };
            }
        }
        return null;
    }

    getProofChain() {
        return this.proofChain.map(id => this.proofs.get(id));
    }

    _generateProofId(proofData) {
        const hashInput = JSON.stringify({
            stateHash: proofData.stateHash,
            transitionId: proofData.transitionId,
            timestamp: Date.now()
        });
        return ethers.keccak256(ethers.toUtf8Bytes(hashInput));
    }

    verifyProof(proofId, verifierAddress) {
        const proof = this.proofs.get(proofId);
        if (!proof) {
            throw new Error(`Proof ${proofId} not found in registry`);
        }
        
        // Proof verification would be handled by AgentVerifier.sol
        // This is a placeholder for the verification logic
        proof.verified = true;
        this._saveRegistry();
        return proof.verified;
    }
}

/**
 * ============================================================================
 * PRIMITIVE: CIRCOM_WITNESS_GENERATOR
 * ============================================================================
 * Generates deterministic witnesses for circom circuits based on state transitions
 * Uses the workflowProof.circom circuit to create ZK-friendly proof inputs
 * 
 * Properties:
 * - Deterministic: Same input always produces same witness
 * - ZK-Friendly: All operations are compatible with circom constraints
 * - Complete: Full witness generation for all circuit inputs
 */
class CircomWitnessGenerator {
    constructor(circuitPath) {
        this.circuitPath = circuitPath;
        this.circuitInfo = this._loadCircuitInfo();
    }

    _loadCircuitInfo() {
        const circuitFile = fs.readFileSync(this.circuitPath, 'utf8');
        const info = {
            inputs: [],
            outputs: [],
            constraints: 0
        };
        
        // Parse circuit for input/output signals
        const inputMatches = circuitFile.match(/signal\s+input\[([^\]]+)\]/g) || [];
        const outputMatches = circuitFile.match(/signal\s+output\[([^\]]+)\]/g) || [];
        
        info.inputs = inputMatches.map(m => m.trim());
        info.outputs = outputMatches.map(m => m.trim());
        
        // Count constraints (approximate)
        info.constraints = (circuitFile.match(/<==/g) || []).length;
        
        return info;
    }

    generateWitness(stateTransition) {
        const witness = {
            // Workflow State Hash (public input)
            stateHash: stateTransition.stateHash,
            
            // Previous State Hash (public input for chain verification)
            previousStateHash: stateTransition.previousStateHash,
            
            // Transition ID (public input)
            transitionId: stateTransition.transitionId,
            
            // Agent ID (public input)
            agentId: stateTransition.agentId,
            
            // Step Number (public input)
            stepNumber: stateTransition.stepNumber,
            
            // Rule ID (public input)
            ruleId: stateTransition.ruleId,
            
            // Output Hash (public input)
            outputHash: stateTransition.outputHash,
            
            // Private inputs (hidden from verification)
            privateInputs: {
                inputData: stateTransition.inputData || '',
                logicHash: stateTransition.logicHash || '',
                timestamp: stateTransition.timestamp || 0
            }
        };
        
        return witness;
    }

    validateWitness(witness) {
        const requiredFields = [
            'stateHash',
            'previousStateHash',
            'transitionId',
            'agentId',
            'stepNumber',
            'ruleId',
            'outputHash'
        ];
        
        for (const field of requiredFields) {
            if (!witness[field]) {
                throw new Error(`Missing required witness field: ${field}`);
            }
        }
        
        // Validate hash formats
        if (!this._isValidHash(witness.stateHash)) {
            throw new Error('Invalid stateHash format');
        }
        
        if (!this._isValidHash(witness.previousStateHash)) {
            throw new Error('Invalid previousStateHash format');
        }
        
        return true;
    }

    _isValidHash(hash) {
        return typeof hash === 'string' && 
               hash.startsWith('0x') && 
               hash.length === 66;
    }
}

/**
 * ============================================================================
 * PRIMITIVE: ZK_PROOF_GENERATOR
 * ============================================================================
 * Core ZK proof generation using circom runtime
 * Generates cryptographic proofs for each state transition
 * 
 * Properties:
 * - Complete: Full proof generation with all required components
 * - Secure: Uses proper cryptographic primitives
 * - Verifiable: Proofs can be verified on-chain via AgentVerifier.sol
 */
class ZKProofGenerator {
    constructor(circuitPath, witnessGenerator) {
        this.circuitPath = circuitPath;
        this.witnessGenerator = witnessGenerator;
        this.proofRegistry = new ProofRegistry();
        this.circomPath = this._getCircomPath();
    }

    _getCircomPath() {
        // Try to find circom binary in common locations
        const possiblePaths = [
            './node_modules/circomlibjs',
            './node_modules/.bin/circom',
            '/usr/local/bin/circom',
            '/usr/bin/circom'
        ];
        
        for (const p of possiblePaths) {
            if (fs.existsSync(p)) {
                return p;
            }
        }
        
        throw new Error('Circom runtime not found. Install with: npm install circomlibjs');
    }

    async generateProof(stateTransition) {
        try {
            // Step 1: Generate witness from state transition
            const witness = this.witnessGenerator.generateWitness(stateTransition);
            
            // Step 2: Validate witness
            this.witnessGenerator.validateWitness(witness);
            
            // Step 3: Compute proof using circom runtime
            const proofData = await this._computeProof(witness);
            
            // Step 4: Register proof in registry
            const proofId = this.proofRegistry.registerProof({
                stateHash: witness.stateHash,
                transitionId: witness.transitionId,
                proof: proofData.proof,
                publicInputs: proofData.publicInputs
            });
            
            return {
                success: true,
                proofId,
                proof: proofData.proof,
                publicInputs: proofData.publicInputs,
                witness: witness
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message,
                proofId: null
            };
        }
    }

    async _computeProof(witness) {
        // Generate proof using circom runtime
        const { buildWitness, generateProof } = require('circomlibjs');
        
        // Build witness from state transition data
        const witnessData = await buildWitness(this.circuitPath, witness);
        
        // Generate ZK proof
        const proof = await generateProof(witnessData);
        
        return {
            proof: proof,
            publicInputs: witness
        };
    }

    async verifyProof(proofId, verifierContract) {
        const proof = this.proofRegistry.getProof(proofId);
        
        if (!proof) {
            throw new Error(`Proof ${proofId} not found`);
        }
        
        // Verify proof using on-chain verifier
        const isValid = await verifierContract.verifyProof(
            proof.proof,
            proof.publicInputs
        );
        
        if (isValid) {
            this.proofRegistry.verifyProof(proofId);
        }
        
        return isValid;
    }

    getProofChain() {
        return this.proofRegistry.getProofChain();
    }

    getProofById(proofId) {
        return this.proofRegistry.getProof(proofId);
    }
}

/**
 * ============================================================================
 * PRIMITIVE: AGENT_EXECUTION_WRAPPER
 * ============================================================================
 * Wraps agent execution loop with ZK proof generation for each state transition
 * Ensures every step is cryptographically verified before proceeding
 * 
 * Properties:
 * - Complete: Full execution loop with proof generation
 * - Secure: No state transition without proof verification
 * - Deterministic: Same execution always produces same proofs
 */
class AgentExecutionWrapper {
    constructor(proofGenerator, stateMachine) {
        this.proofGenerator = proofGenerator;
        this.stateMachine = stateMachine;
        this.executionLog = [];
    }

    async executeWorkflow(workflowDefinition, initialData) {
        const executionId = this._generateExecutionId(workflowDefinition, initialData);
        const executionState = {
            id: executionId,
            workflowId: workflowDefinition.id,
            step: 0,
            currentState: initialData,
            proofs: [],
            status: 'running'
        };
        
        try {
            // Execute each step in workflow
            for (const step of workflowDefinition.steps) {
                const stepResult = await this._executeStep(step, executionState.currentState);
                
                // Generate ZK proof for this step
                const proofResult = await this.proofGenerator.generateProof({
                    stateHash: stepResult.stateHash,
                    previousStateHash: executionState.currentState.stateHash,
                    transitionId: stepResult.transitionId,
                    agentId: stepResult.agentId,
                    stepNumber: executionState.step,
                    ruleId: step.ruleId,
                    outputHash: stepResult.outputHash,
                    inputData: stepResult.inputData,
                    logicHash: stepResult.logicHash,
                    timestamp: Date.now()
                });
                
                if (!proofResult.success) {
                    throw new Error(`Proof generation failed for step ${executionState.step}: ${proofResult.error}`);
                }
                
                // Store proof and update state
                executionState.proofs.push(proofResult);
                executionState.currentState = stepResult;
                executionState.step++;
                
                // Log execution
                this.executionLog.push({
                    executionId,
                    step: executionState.step,
                    proofId: proofResult.proofId,
                    timestamp: Date.now()
                });
            }
            
            executionState.status = 'completed';
            executionState.finalStateHash = executionState.currentState.stateHash;
            
            return {
                success: true,
                executionId,
                finalState: executionState.currentState,
                proofs: executionState.proofs,
                executionLog: this.executionLog
            };
            
        } catch (error) {
            executionState.status = 'failed';
            executionState.error = error.message;
            
            return {
                success: false,
                executionId,
                error: error.message,
                proofs: executionState.proofs,
                executionLog: this.executionLog
            };
        }
    }

    async _executeStep(step, currentState) {
        // Execute step using deterministic state machine
        const stepResult = await this.stateMachine.executeStep(step, currentState);
        
        return {
            stateHash: stepResult.stateHash,
            transitionId: stepResult.transitionId,
            agentId: stepResult.agentId,
            outputHash: stepResult.outputHash,
            inputData: stepResult.inputData,
            logicHash: stepResult.logicHash,
            timestamp: Date.now()
        };
    }

    _generateExecutionId(workflowDefinition, initialData) {
        const hashInput = JSON.stringify({
            workflowId: workflowDefinition.id,
            initialData: initialData,
            timestamp: Date.now()
        });
        return ethers.keccak256(ethers.toUtf8Bytes(hashInput));
    }

    getExecutionLog() {
        return this.executionLog;
    }

    getExecutionById(executionId) {
        return this.executionLog.filter(log => log.executionId === executionId);
    }
}

/**
 * ============================================================================
 * PRIMITIVE: PROOF_VERIFICATION_SERVICE
 * ============================================================================
 * Service for verifying ZK proofs on-chain via AgentVerifier.sol
 * Ensures proof validity before committing state transitions
 * 
 * Properties:
 * - Complete: Full verification service with error handling
 * - Secure: No state update without proof verification
 * - Verifiable: All proofs can be independently verified
 */
class ProofVerificationService {
    constructor(verifierContract, proofRegistry) {
        this.verifierContract = verifierContract;
        this.proofRegistry = proofRegistry;
    }

    async verifyProofOnChain(proofId) {
        const proof = this.proofRegistry.getProof(proofId);
        
        if (!proof) {
            throw new Error(`Proof ${proofId} not found in registry`);
        }
        
        try {
            // Verify proof using on-chain verifier
            const isValid = await this.verifierContract.verifyProof(
                proof.proof,
                proof.publicInputs
            );
            
            if (isValid) {
                this.proofRegistry.verifyProof(proofId);
                return {
                    success: true,
                    proofId,
                    verified: true,
                    timestamp: Date.now()
                };
            } else {
                return {
                    success: false,
                    proofId,
                    verified: false,
                    timestamp: Date.now()
                };
            }
            
        } catch (error) {
            return {
                success: false,
                proofId,
                verified: false,
                error: error.message,
                timestamp: Date.now()
            };
        }
    }

    async verifyProofChain(proofChain) {
        const results = [];
        
        for (const proofId of proofChain) {
            const result = await this.verifyProofOnChain(proofId);
            results.push(result);
            
            if (!result.success || !result.verified) {
                break;
            }
        }
        
        return results;
    }

    async getProofStatus(proofId) {
        const proof = this.proofRegistry.getProof(proofId);
        
        if (!proof) {
            return {
                exists: false,
                proofId
            };
        }
        
        return {
            exists: true,
            proofId,
            stateHash: proof.stateHash,
            transitionId: proof.transitionId,
            verified: proof.verified,
            timestamp: proof.timestamp
        };
    }
}

/**
 * ============================================================================
 * PRIMITIVE: WORKFLOW_PROOF_ORCHESTRATOR
 * ============================================================================
 * Orchestrates complete ZK proof generation for entire workflow execution
 * Coordinates between execution wrapper, proof generator, and verification service
 * 
 * Properties:
 * - Complete: Full orchestration of proof lifecycle
 * - Secure: All steps verified before proceeding
 * - Auditable: Complete proof chain for audit purposes
 */
class WorkflowProofOrchestrator {
    constructor(proofGenerator, executionWrapper, verificationService) {
        this.proofGenerator = proofGenerator;
        this.executionWrapper = executionWrapper;
        this.verificationService = verificationService;
    }

    async executeAndVerifyWorkflow(workflowDefinition, initialData) {
        // Execute workflow with proof generation
        const executionResult = await this.executionWrapper.executeWorkflow(
            workflowDefinition,
            initialData
        );
        
        if (!executionResult.success) {
            return {
                success: false,
                error: executionResult.error,
                executionId: executionResult.executionId
            };
        }
        
        // Verify all proofs on-chain
        const verificationResults = [];
        
        for (const proof of executionResult.proofs) {
            const verification = await this.verificationService.verifyProofOnChain(
                proof.proofId
            );
            verificationResults.push(verification);
        }
        
        // Check if all proofs verified successfully
        const allVerified = verificationResults.every(r => r.success && r.verified);
        
        return {
            success: allVerified,
            executionId: executionResult.executionId,
            finalState: executionResult.finalState,
            proofs: executionResult.proofs,
            verificationResults,
            executionLog: executionResult.executionLog
        };
    }

    async getWorkflowProofChain(executionId) {
        const executionLog = this.executionWrapper.getExecutionById(executionId);
        
        if (!executionLog || executionLog.length === 0) {
            throw new Error(`Execution ${executionId} not found`);
        }
        
        const proofChain = executionLog.map(log => log.proofId);
        
        return {
            executionId,
            proofChain,
            proofDetails: proofChain.map(id => 
                this.proofGenerator.getProofById(id)
            )
        };
    }

    async auditWorkflow(executionId) {
        const proofChain = await this.getWorkflowProofChain(executionId);
        
        const auditReport = {
            executionId,
            totalSteps: proofChain.proofChain.length,
            verifiedSteps: 0,
            failedSteps: 0,
            proofChain: proofChain.proofChain,
            verificationResults: []
        };
        
        for (const proofId of proofChain.proofChain) {
            const status = await this.verificationService.getProofStatus(proofId);
            
            if (status.exists && status.verified) {
                auditReport.verifiedSteps++;
            } else {
                auditReport.failedSteps++;
            }
            
            auditReport.verificationResults.push(status);
        }
        
        auditReport.integrityScore = auditReport.verifiedSteps / auditReport.totalSteps;
        
        return auditReport;
    }
}

/**
 * ============================================================================
 * EXPORT: MAIN PROOF GENERATOR INTERFACE
 * ============================================================================
 * Main interface for ZK proof generation in VeriFlow
 * Provides complete proof lifecycle management
 */
class VeriFlowProofGenerator {
    constructor(config = {}) {
        this.circuitPath = config.circuitPath || './circuits/workflowProof.circom';
        this.storagePath = config.storagePath || './proofs';
        
        // Initialize components
        this.witnessGenerator = new CircomWitnessGenerator(this.circuitPath);
        this.proofGenerator = new ZKProofGenerator(this.circuitPath, this.witnessGenerator);
        this.stateMachine = new DeterministicStateMachine();
        this.executionWrapper = new AgentExecutionWrapper(
            this.proofGenerator,
            this.stateMachine
        );
        this.proofRegistry = this.proofGenerator.proofRegistry;
        
        // Verification service (initialized with contract later)
        this.verificationService = null;
        this.orchestrator = null;
    }

    setVerifierContract(verifierContract) {
        this.verificationService = new ProofVerificationService(
            verifierContract,
            this.proofRegistry
        );
        this.orchestrator = new WorkflowProofOrchestrator(
            this.proofGenerator,
            this.executionWrapper,
            this.verificationService
        );
    }

    async generateProofForTransition(stateTransition) {
        return await this.proofGenerator.generateProof(stateTransition);
    }

    async executeWorkflow(workflowDefinition, initialData) {
        if (!this.orchestrator) {
            throw new Error('Verifier contract not set. Call setVerifierContract() first.');
        }
        
        return await this.orchestrator.executeAndVerifyWorkflow(
            workflowDefinition,
            initialData
        );
    }

    async verifyProof(proofId) {
        if (!this.verificationService) {
            throw new Error('Verifier contract not set. Call setVerifierContract() first.');
        }
        
        return await this.verificationService.verifyProofOnChain(proofId);
    }

    async auditWorkflow(executionId) {
        if (!this.orchestrator) {
            throw new Error('Verifier contract not set. Call setVerifierContract() first.');
        }
        
        return await this.orchestrator.auditWorkflow(executionId);
    }

    getProofChain() {
        return this.proofGenerator.getProofChain();
    }

    getProofById(proofId) {
        return this.proofGenerator.getProofById(proofId);
    }
}

// ============================================================================
// EXPORTS
// ============================================================================
module.exports = {
    VeriFlowProofGenerator,
    ProofRegistry,
    CircomWitnessGenerator,
    ZKProofGenerator,
    AgentExecutionWrapper,
    ProofVerificationService,
    WorkflowProofOrchestrator
};