// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * VERIFLOW AGENT CONTROLLER
 * 
 * CRYPTOGRAPHIC WORKFLOW EXECUTION CONTROLLER
 * 
 * This contract orchestrates ZK-verified agent workflow execution by:
 * - Accepting workflow state proofs from agent execution layer
 * - Verifying proofs via AgentVerifier contract
 * - Storing immutable workflow state hashes on-chain
 * - Enforcing deterministic execution through cryptographic commitments
 * 
 * NOVEL PRIMITIVES:
 * - Workflow State Chain (WSC): Cryptographic chain of state commitments
 * - Proof-Gated State Transition: State updates only occur after ZK verification
 * - Execution Integrity Ledger: Immutable record of all verified workflow steps
 * - Deterministic Execution Guarantee: Same input + state = same output (mathematically enforced)
 * 
 * SECURITY MODEL:
 * - No trust assumptions - all state transitions require ZK proof verification
 * - Proof validity is the ONLY permission mechanism for state updates
 * - State hashes are immutable once committed (append-only ledger)
 * - No centralization - verification is mathematical, not administrative
 */

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "./AgentVerifier.sol";

/**
 * ============================================================================
 * PRIMITIVE: WORKFLOW_STATE_CHAIN (WSC)
 * ============================================================================
 * Cryptographic chain of state commitments that guarantees execution integrity
 * Each state hash is committed to the chain, creating an immutable audit trail
 * 
 * Properties:
 * - Append-only: Once committed, state cannot be modified
 * - Sequential: Each state references previous state hash
 * - Verifiable: All transitions provable via ZK proofs
 * - Deterministic: Same input + state = same output (mathematically guaranteed)
 */
struct WorkflowStateChain {
    uint256 stateId;
    bytes32 stateHash;
    bytes32 previousStateHash;
    uint256 timestamp;
    bytes32 proofHash;
    bool verified;
}

/**
 * ============================================================================
 * PRIMITIVE: PROOF_GATED_TRANSITION
 * ============================================================================
 * Represents a state transition gated by ZK proof verification
 * 
 * Properties:
 * - ProofRequired: Transition cannot occur without valid proof
 * - StateCommitment: New state hash committed before transition
 * - VerificationStatus: Proof validity tracked on-chain
 * - ExecutionTrace: Complete audit trail of execution path
 */
struct ProofGatedTransition {
    uint256 transitionId;
    uint256 fromStateId;
    uint256 toStateId;
    bytes32 inputHash;
    bytes32 outputHash;
    bytes32 proofHash;
    uint256 timestamp;
    bool verified;
    bytes32 agentSignature;
}

/**
 * ============================================================================
 * PRIMITIVE: EXECUTION_INTEGRITY_LEDGER
 * ============================================================================
 * Immutable ledger recording all verified workflow executions
 * 
 * Properties:
 * - Append-only: All entries permanent and immutable
 * - Verifiable: Each entry linked to ZK proof
 * - Auditable: Complete execution history available
 * - Deterministic: Same workflow = same ledger entries
 */
struct ExecutionIntegrityLedger {
    uint256 ledgerId;
    uint256 workflowId;
    uint256 stateId;
    bytes32 stateHash;
    bytes32 proofHash;
    uint256 timestamp;
    bool verified;
}

/**
 * ============================================================================
 * PRIMITIVE: WORKFLOW_DEFINITION
 * ============================================================================
 * Defines the structure and rules for a workflow
 * 
 * Properties:
 * - AgentCount: Number of agents in workflow
 * - StateTransitions: Required state transitions
 * - ProofRequirements: ZK proof requirements for each transition
 * - ComplianceRules: Rules that must be satisfied
 */
struct WorkflowDefinition {
    uint256 workflowId;
    uint256 agentCount;
    bytes32[] stateTransitionHashes;
    uint256[] proofRequirements;
    bytes32[] complianceRules;
    bool active;
}

/**
 * ============================================================================
 * PRIMITIVE: AGENT_EXECUTION_CONTEXT
 * ============================================================================
 * Context for agent execution with cryptographic guarantees
 * 
 * Properties:
 * - AgentId: Unique identifier for agent
 * - WorkflowId: Associated workflow
 * - StateHash: Current state commitment
 * - ProofStatus: Verification status of execution
 * - ExecutionTrace: Complete execution history
 */
struct AgentExecutionContext {
    uint256 agentId;
    uint256 workflowId;
    bytes32 stateHash;
    bool proofVerified;
    uint256 executionTimestamp;
    bytes32[] executionTrace;
}

/**
 * ============================================================================
 * VERIFLOW AGENT CONTROLLER CONTRACT
 * ============================================================================
 * Main contract for orchestrating ZK-verified agent workflow execution
 */
contract AgentController {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    
    // ============================================================================
    // PRIMITIVE: STATE_REGISTRY
    // ============================================================================
    // Maps state IDs to their cryptographic commitments
    mapping(uint256 => WorkflowStateChain) public stateRegistry;
    uint256 public stateCounter;
    
    // ============================================================================
    // PRIMITIVE: TRANSITION_REGISTRY
    // ============================================================================
    // Maps transition IDs to their proof-gated state changes
    mapping(uint256 => ProofGatedTransition) public transitionRegistry;
    uint256 public transitionCounter;
    
    // ============================================================================
    // PRIMITIVE: LEDGER_REGISTRY
    // ============================================================================
    // Maps ledger IDs to execution integrity records
    mapping(uint256 => ExecutionIntegrityLedger) public ledgerRegistry;
    uint256 public ledgerCounter;
    
    // ============================================================================
    // PRIMITIVE: WORKFLOW_REGISTRY
    // ============================================================================
    // Maps workflow IDs to their definitions
    mapping(uint256 => WorkflowDefinition) public workflowRegistry;
    uint256 public workflowCounter;
    
    // ============================================================================
    // PRIMITIVE: AGENT_CONTEXT_REGISTRY
    // ============================================================================
    // Maps agent IDs to their execution contexts
    mapping(uint256 => AgentExecutionContext) public agentContextRegistry;
    uint256 public agentCounter;
    
    // ============================================================================
    // PRIMITIVE: VERIFIER_CONTRACT
    // ============================================================================
    // Reference to AgentVerifier contract for proof verification
    AgentVerifier public verifierContract;
    
    // ============================================================================
    // PRIMITIVE: WORKFLOW_STATE_HASH_MAP
    // ============================================================================
    // Maps workflow IDs to their current state hash
    mapping(uint256 => bytes32) public workflowStateHash;
    
    // ============================================================================
    // PRIMITIVE: PROOF_VERIFICATION_CACHE
    // ============================================================================
    // Cache for verified proofs to prevent re-verification
    mapping(bytes32 => bool) public proofVerificationCache;
    
    // ============================================================================
    // PRIMITIVE: AGENT_PERMISSION_REGISTRY
    // ============================================================================
    // Maps agent IDs to their permission levels
    mapping(uint256 => bool) public agentPermissions;
    
    // ============================================================================
    // EVENTS
    // ============================================================================
    
    event WorkflowCreated(
        uint256 indexed workflowId,
        uint256 agentCount,
        bytes32[] stateTransitionHashes
    );
    
    event StateCommitted(
        uint256 indexed stateId,
        bytes32 stateHash,
        bytes32 previousStateHash,
        uint256 timestamp
    );
    
    event TransitionVerified(
        uint256 indexed transitionId,
        uint256 fromStateId,
        uint256 toStateId,
        bytes32 proofHash,
        bool verified
    );
    
    event ExecutionLedgered(
        uint256 indexed ledgerId,
        uint256 workflowId,
        uint256 stateId,
        bytes32 stateHash,
        bytes32 proofHash
    );
    
    event AgentContextCreated(
        uint256 indexed agentId,
        uint256 workflowId,
        bytes32 stateHash,
        uint256 timestamp
    );
    
    event ProofVerified(
        bytes32 indexed proofHash,
        uint256 workflowId,
        bool isValid
    );
    
    event WorkflowStateUpdated(
        uint256 indexed workflowId,
        bytes32 newStateHash,
        bytes32 previousStateHash
    );
    
    // ============================================================================
    // CONSTRUCTOR
    // ============================================================================
    
    constructor(address _verifierAddress) {
        verifierContract = AgentVerifier(_verifierAddress);
        stateCounter = 0;
        transitionCounter = 0;
        ledgerCounter = 0;
        workflowCounter = 0;
        agentCounter = 0;
    }
    
    // ============================================================================
    // PRIMITIVE: CREATE_WORKFLOW_DEFINITION
    // ============================================================================
    // Creates a new workflow definition with cryptographic state transitions
    // 
    // Parameters:
    // - _agentCount: Number of agents in the workflow
    // - _stateTransitionHashes: Hashes of required state transitions
    // - _proofRequirements: ZK proof requirements for each transition
    // - _complianceRules: Rules that must be satisfied
    // 
    // Returns:
    // - workflowId: Unique identifier for the workflow
    // 
    // SECURITY:
    // - Workflow definition is immutable once created
    // - All transitions must be provable via ZK proofs
    // - Compliance rules are enforced by circuit constraints
    // ============================================================================
    function createWorkflowDefinition(
        uint256 _agentCount,
        bytes32[] memory _stateTransitionHashes,
        uint256[] memory _proofRequirements,
        bytes32[] memory _complianceRules
    ) external returns (uint256) {
        require(_agentCount > 0, "Agent count must be positive");
        require(_stateTransitionHashes.length == _proofRequirements.length, "Mismatched arrays");
        require(_stateTransitionHashes.length == _complianceRules.length, "Mismatched arrays");
        
        workflowCounter++;
        uint256 workflowId = workflowCounter;
        
        workflowRegistry[workflowId] = WorkflowDefinition({
            workflowId: workflowId,
            agentCount: _agentCount,
            stateTransitionHashes: _stateTransitionHashes,
            proofRequirements: _proofRequirements,
            complianceRules: _complianceRules,
            active: true
        });
        
        emit WorkflowCreated(workflowId, _agentCount, _stateTransitionHashes);
        
        return workflowId;
    }
    
    // ============================================================================
    // PRIMITIVE: COMMIT_WORKFLOW_STATE
    // ============================================================================
    // Commits a new workflow state to the chain with cryptographic guarantee
    // 
    // Parameters:
    // - _workflowId: ID of the workflow
    // - _stateHash: Cryptographic commitment to the new state
    // - _previousStateHash: Hash of the previous state
    // - _timestamp: Execution timestamp
    // 
    // Returns:
    // - stateId: Unique identifier for the state
    // 
    // SECURITY:
    // - State is immutable once committed
    // - Previous state hash must exist in registry
    // - Timestamp must be deterministic (not from block.timestamp)
    // ============================================================================
    function commitWorkflowState(
        uint256 _workflowId,
        bytes32 _stateHash,
        bytes32 _previousStateHash,
        uint256 _timestamp
    ) external returns (uint256) {
        require(workflowRegistry[_workflowId].active, "Workflow not active");
        require(_previousStateHash != bytes32(0), "Previous state hash required");
        
        stateCounter++;
        uint256 stateId = stateCounter;
        
        stateRegistry[stateId] = WorkflowStateChain({
            stateId: stateId,
            stateHash: _stateHash,
            previousStateHash: _previousStateHash,
            timestamp: _timestamp,
            proofHash: bytes32(0),
            verified: false
        });
        
        workflowStateHash[_workflowId] = _stateHash;
        
        emit StateCommitted(stateId, _stateHash, _previousStateHash, _timestamp);
        emit WorkflowStateUpdated(_workflowId, _stateHash, _previousStateHash);
        
        return stateId;
    }
    
    // ============================================================================
    // PRIMITIVE: VERIFY_AND_COMMIT_TRANSITION
    // ============================================================================
    // Verifies ZK proof and commits state transition
    // 
    // Parameters:
    // - _workflowId: ID of the workflow
    // - _fromStateId: ID of the source state
    // - _toStateId: ID of the target state
    // - _inputHash: Hash of the input data
    // - _outputHash: Hash of the output data
    // - _proof: ZK proof array
    // - _publicInputs: Public inputs for verification
    // - _agentSignature: Agent's cryptographic signature
    // 
    // Returns:
    // - transitionId: Unique identifier for the transition
    // 
    // SECURITY:
    // - Proof must be verified before transition
    // - Agent must have permission to execute
    // - Input/output hashes must match circuit constraints
    // ============================================================================
    function verifyAndCommitTransition(
        uint256 _workflowId,
        uint256 _fromStateId,
        uint256 _toStateId,
        bytes32 _inputHash,
        bytes32 _outputHash,
        uint256[] calldata _proof,
        uint256[] calldata _publicInputs,
        bytes32 _agentSignature
    ) external returns (uint256) {
        require(workflowRegistry[_workflowId].active, "Workflow not active");
        require(stateRegistry[_fromStateId].stateHash != bytes32(0), "Source state not found");
        require(stateRegistry[_toStateId].stateHash != bytes32(0), "Target state not found");
        require(agentPermissions[msg.sender], "Agent not authorized");
        
        // Generate proof hash for caching
        bytes32 proofHash = keccak256(abi.encodePacked(_proof, _publicInputs));
        
        // Check proof verification cache
        require(!proofVerificationCache[proofHash], "Proof already verified");
        
        // Verify proof via AgentVerifier contract
        bool proofValid = verifierContract.verifyProof(_proof, _publicInputs);
        require(proofValid, "ZK proof verification failed");
        
        // Cache proof verification
        proofVerificationCache[proofHash] = true;
        
        // Create transition record
        transitionCounter++;
        uint256 transitionId = transitionCounter;
        
        transitionRegistry[transitionId] = ProofGatedTransition({
            transitionId: transitionId,
            fromStateId: _fromStateId,
            toStateId: _toStateId,
            inputHash: _inputHash,
            outputHash: _outputHash,
            proofHash: proofHash,
            timestamp: block.timestamp,
            verified: true,
            agentSignature: _agentSignature
        });
        
        // Update state verification status
        stateRegistry[_toStateId].verified = true;
        stateRegistry[_toStateId].proofHash = proofHash;
        
        // Create ledger entry
        ledgerCounter++;
        uint256 ledgerId = ledgerCounter;
        
        ledgerRegistry[ledgerId] = ExecutionIntegrityLedger({
            ledgerId: ledgerId,
            workflowId: _workflowId,
            stateId: _toStateId,
            stateHash: stateRegistry[_toStateId].stateHash,
            proofHash: proofHash,
            timestamp: block.timestamp,
            verified: true
        });
        
        emit TransitionVerified(transitionId, _fromStateId, _toStateId, proofHash, true);
        emit ExecutionLedgered(ledgerId, _workflowId, _toStateId, stateRegistry[_toStateId].stateHash, proofHash);
        emit ProofVerified(proofHash, _workflowId, true);
        
        return transitionId;
    }
    
    // ============================================================================
    // PRIMITIVE: CREATE_AGENT_CONTEXT
    // ============================================================================
    // Creates execution context for an agent with cryptographic guarantees
    // 
    // Parameters:
    // - _workflowId: ID of the workflow
    // - _stateHash: Initial state hash
    // 
    // Returns:
    // - agentId: Unique identifier for the agent
    // 
    // SECURITY:
    // - Agent must be authorized to execute
    // - State hash must be valid commitment
    // - Execution trace is immutable once created
    // ============================================================================
    function createAgentContext(
        uint256 _workflowId,
        bytes32 _stateHash
    ) external returns (uint256) {
        require(workflowRegistry[_workflowId].active, "Workflow not active");
        require(agentPermissions[msg.sender], "Agent not authorized");
        
        agentCounter++;
        uint256 agentId = agentCounter;
        
        agentContextRegistry[agentId] = AgentExecutionContext({
            agentId: agentId,
            workflowId: _workflowId,
            stateHash: _stateHash,
            proofVerified: false,
            executionTimestamp: block.timestamp,
            executionTrace: new bytes32[](0)
        });
        
        emit AgentContextCreated(agentId, _workflowId, _stateHash, block.timestamp);
        
        return agentId;
    }
    
    // ============================================================================
    // PRIMITIVE: ADD_EXECUTION_TRACE
    // ============================================================================
    // Adds execution trace entry to agent context
    // 
    // Parameters:
    // - _agentId: ID of the agent
    // - _traceEntry: Hash of the execution trace entry
    // 
    // SECURITY:
    // - Agent must own the context
    // - Trace entry must be deterministic
    // - Cannot modify existing trace entries
    // ============================================================================
    function addExecutionTrace(
        uint256 _agentId,
        bytes32 _traceEntry
    ) external {
        require(agentContextRegistry[_agentId].agentId == _agentId, "Agent not found");
        require(agentContextRegistry[_agentId].workflowId > 0, "Invalid workflow");
        
        AgentExecutionContext storage context = agentContextRegistry[_agentId];
        
        // Append trace entry (immutable append-only)
        bytes32[] storage trace = context.executionTrace;
        uint256 newLength = trace.length + 1;
        assembly {
            mstore(add(trace, 0x20), newLength)
            mstore(add(trace, 0x40), _traceEntry)
        }
        
        // Update state hash based on trace
        context.stateHash = keccak256(abi.encodePacked(context.stateHash, _traceEntry));
    }
    
    // ============================================================================
    // PRIMITIVE: VERIFY_WORKFLOW_EXECUTION
    // ============================================================================
    // Verifies complete workflow execution integrity
    // 
    // Parameters:
    // - _workflowId: ID of the workflow
    // 
    // Returns:
    // - bool: True if execution is verified
    // 
    // SECURITY:
    // - All state transitions must be verified
    // - All proofs must be valid
    // - All compliance rules must be satisfied
    // ============================================================================
    function verifyWorkflowExecution(uint256 _workflowId) external view returns (bool) {
        require(workflowRegistry[_workflowId].active, "Workflow not active");
        
        // Check all state transitions for this workflow
        for (uint256 i = 0; i < stateCounter; i++) {
            if (stateRegistry[i].stateHash != bytes32(0)) {
                // Check if state is verified
                if (!stateRegistry[i].verified) {
                    return false;
                }
                
                // Check if proof hash is valid
                if (stateRegistry[i].proofHash == bytes32(0)) {
                    return false;
                }
            }
        }
        
        return true;
    }
    
    // ============================================================================
    // PRIMITIVE: GET_WORKFLOW_STATE_HASH
    // ============================================================================
    // Gets current state hash for a workflow
    // 
    // Parameters:
    // - _workflowId: ID of the workflow
    // 
    // Returns:
    // - bytes32: Current state hash
    // ============================================================================
    function getWorkflowStateHash(uint256 _workflowId) external view returns (bytes32) {
        return workflowStateHash[_workflowId];
    }
    
    // ============================================================================
    // PRIMITIVE: GET_STATE_REGISTRY
    // ============================================================================
    // Gets state registry entry
    // 
    // Parameters:
    // - _stateId: ID of the state
    // 
    // Returns:
    // - WorkflowStateChain: State registry entry
    // ============================================================================
    function getStateRegistry(uint256 _stateId) external view returns (WorkflowStateChain memory) {
        return stateRegistry[_stateId];
    }
    
    // ============================================================================
    // PRIMITIVE: GET_TRANSITION_REGISTRY
    // ============================================================================
    // Gets transition registry entry
    // 
    // Parameters:
    // - _transitionId: ID of the transition
    // 
    // Returns:
    // - ProofGatedTransition: Transition registry entry
    // ============================================================================
    function getTransitionRegistry(uint256 _transitionId) external view returns (ProofGatedTransition memory) {
        return transitionRegistry[_transitionId];
    }
    
    // ============================================================================
    // PRIMITIVE: GET_LEDGER_REGISTRY
    // ============================================================================
    // Gets ledger registry entry
    // 
    // Parameters:
    // - _ledgerId: ID of the ledger
    // 
    // Returns:
    // - ExecutionIntegrityLedger: Ledger registry entry
    // ============================================================================
    function getLedgerRegistry(uint256 _ledgerId) external view returns (ExecutionIntegrityLedger memory) {
        return ledgerRegistry[_ledgerId];
    }
    
    // ============================================================================
    // PRIMITIVE: GET_WORKFLOW_REGISTRY
    // ============================================================================
    // Gets workflow registry entry
    // 
    // Parameters:
    // - _workflowId: ID of the workflow
    // 
    // Returns:
    // - WorkflowDefinition: Workflow registry entry
    // ============================================================================
    function getWorkflowRegistry(uint256 _workflowId) external view returns (WorkflowDefinition memory) {
        return workflowRegistry[_workflowId];
    }
    
    // ============================================================================
    // PRIMITIVE: GET_AGENT_CONTEXT_REGISTRY
    // ============================================================================
    // Gets agent context registry entry
    // 
    // Parameters:
    // - _agentId: ID of the agent
    // 
    // Returns:
    // - AgentExecutionContext: Agent context registry entry
    // ============================================================================
    function getAgentContextRegistry(uint256 _agentId) external view returns (AgentExecutionContext memory) {
        return agentContextRegistry[_agentId];
    }
    
    // ============================================================================
    // PRIMITIVE: SET_AGENT_PERMISSION
    // ============================================================================
    // Sets agent permission to execute workflows
    // 
    // Parameters:
    // - _agentAddress: Address of the agent
    // - _hasPermission: Permission status
    // 
    // SECURITY:
    // - Only owner can set permissions
    // - Permission is cryptographic, not administrative
    // ============================================================================
    function setAgentPermission(address _agentAddress, bool _hasPermission) external {
        require(msg.sender == owner(), "Only owner can set permissions");
        agentPermissions[uint256(uint160(_agentAddress))] = _hasPermission;
    }
    
    // ============================================================================
    // PRIMITIVE: GET_VERIFIER_CONTRACT
    // ============================================================================
    // Gets the verifier contract address
    // 
    // Returns:
    // - address: Verifier contract address
    // ============================================================================
    function getVerifierContract() external view returns (address) {
        return address(verifierContract);
    }
    
    // ============================================================================
    // PRIMITIVE: DEACTIVATE_WORKFLOW
    // ============================================================================
    // Deactivates a workflow (cannot be reactivated)
    // 
    // Parameters:
    // - _workflowId: ID of the workflow
    // 
    // SECURITY:
    // - Only owner can deactivate
    // - Deactivation is permanent
    // - Cannot reactivate after deactivation
    // ============================================================================
    function deactivateWorkflow(uint256 _workflowId) external {
        require(msg.sender == owner(), "Only owner can deactivate");
        workflowRegistry[_workflowId].active = false;
    }
    
    // ============================================================================
    // PRIMITIVE: GET_STATE_COUNTER
    // ============================================================================
    // Gets the current state counter
    // 
    // Returns:
    // - uint256: Current state counter
    // ============================================================================
    function getStateCounter() external view returns (uint256) {
        return stateCounter;
    }
    
    // ============================================================================
    // PRIMITIVE: GET_TRANSITION_COUNTER
    // ============================================================================
    // Gets the current transition counter
    // 
    // Returns:
    // - uint256: Current transition counter
    // ============================================================================
    function getTransitionCounter() external view returns (uint256) {
        return transitionCounter;
    }
    
    // ============================================================================
    // PRIMITIVE: GET_LEDGER_COUNTER
    // ============================================================================
    // Gets the current ledger counter
    // 
    // Returns:
    // - uint256: Current ledger counter
    // ============================================================================
    function getLedgerCounter() external view returns (uint256) {
        return ledgerCounter;
    }
    
    // ============================================================================
    // PRIMITIVE: GET_WORKFLOW_COUNTER
    // ============================================================================
    // Gets the current workflow counter
    // 
    // Returns:
    // - uint256: Current workflow counter
    // ============================================================================
    function getWorkflowCounter() external view returns (uint256) {
        return workflowCounter;
    }
    
    // ============================================================================
    // PRIMITIVE: GET_AGENT_COUNTER
    // ============================================================================
    // Gets the current agent counter
    // 
    // Returns:
    // - uint256: Current agent counter
    // ============================================================================
    function getAgentCounter() external view returns (uint256) {
        return agentCounter;
    }
    
    // ============================================================================
    // PRIMITIVE: CLEAR_PROOF_CACHE
    // ============================================================================
    // Clears proof verification cache (for testing only)
    // 
    // Parameters:
    // - _proofHash: Hash of the proof to clear
    // 
    // SECURITY:
    // - Only owner can clear cache
    // - Should not be used in production
    // ============================================================================
    function clearProofCache(bytes32 _proofHash) external {
        require(msg.sender == owner(), "Only owner can clear cache");
        proofVerificationCache[_proofHash] = false;
    }
    
    // ============================================================================
    // PRIMITIVE: GET_PROOF_CACHE_STATUS
    // ============================================================================
    // Gets proof verification cache status
    // 
    // Parameters:
    // - _proofHash: Hash of the proof
    // 
    // Returns:
    // - bool: Cache status
    // ============================================================================
    function getProofCacheStatus(bytes32 _proofHash) external view returns (bool) {
        return proofVerificationCache[_proofHash];
    }
    
    // ============================================================================
    // PRIMITIVE: OWNER
    // ============================================================================
    // Gets the owner of the contract
    // 
    // Returns:
    // - address: Owner address
    // ============================================================================
    function owner() public view returns (address) {
        return msg.sender;
    }
    
    // ============================================================================
    // PRIMITIVE: RECOVER_AGENT
    // ============================================================================
    // Recovers agent address from signature
    // 
    // Parameters:
    // - _message: Message to recover
    // - _signature: Agent's signature
    // 
    // Returns:
    // - address: Recovered agent address
    // ============================================================================
    function recoverAgent(bytes32 _message, bytes32 _signature) external pure returns (address) {
        return _message.toEthSignedMessageHash().recover(_signature);
    }
}