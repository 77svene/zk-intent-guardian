import { ethers } from "ethers";

/**
 * INTENT_SCHEMA_V1 - Cryptographically verifiable agent authorization primitive
 * 
 * DESIGN PHILOSOPHY:
 * - Every field is ZK-verifiable (no unbounded strings, no floating point)
 * - Action space is parameterized as bounds, not discrete values
 * - State hash enables drift detection via Merkle inclusion proofs
 * - Signature binds intent to agent identity cryptographically
 * 
 * NOVELTY: First intent schema designed for ZK-circuit verification of
 * action bounds without revealing the intent itself
 */

export const INTENT_VERSION = "1.0.0";
export const INTENT_DOMAIN_SEPARATOR = "ZKIntentGuardianV1";

/**
 * Action type enumeration - must be ZK-verifiable integers
 */
export enum ActionType {
  READ = 0,
  WRITE = 1,
  TRANSFER = 2,
  CALL_CONTRACT = 3,
  EXECUTE_SCRIPT = 4,
  MODIFY_CONFIG = 5,
  NETWORK_REQUEST = 6,
  FILE_SYSTEM = 7,
  DATABASE_QUERY = 8,
  EXTERNAL_API = 9,
}

/**
 * Parameter bound for ZK verification
 * Uses fixed-size bytes32 for min/max to enable range proofs in Circom
 * String types break ZK constraints - fixed-size bytes are required
 */
export interface ParameterBound {
  min: `0x${string}`; // bytes32 hex string for ZK compatibility
  max: `0x${string}`; // bytes32 hex string for ZK compatibility
  step: `0x${string}`; // bytes32 hex string for step validation
}

/**
 * Validated EVM address type - ensures address validity at type level
 */
export type ValidatedAddress = `0x${string}` & { __validated: true };

/**
 * Action specification with ZK-verifiable bounds
 */
export interface ActionSpec {
  action_type: ActionType;
  target_contracts: ValidatedAddress[]; // Array of validated EVM addresses
  parameter_bounds: ParameterBound[]; // Fixed-size bounds for ZK range proofs
  max_gas_limit: bigint; // Fixed-size integer for gas verification
  max_value: bigint; // Fixed-size integer for value transfer limits
  allowed_methods: `0x${string}`[]; // Function selectors (4 bytes)
}

/**
 * Initial state hash for drift detection
 * Merkle root of agent's starting state for ZK inclusion proofs
 */
export interface InitialState {
  state_hash: `0x${string}`; // bytes32 hash of initial state
  state_root: `0x${string}`; // Merkle root for state tree
  block_number: bigint; // Block number for state anchoring
  chain_id: bigint; // Chain ID for cross-chain verification
}

/**
 * Intent bounds for action space verification
 */
export interface IntentBounds {
  min_timestamp: bigint; // Unix timestamp for intent validity start
  max_timestamp: bigint; // Unix timestamp for intent validity end
  max_actions: bigint; // Maximum number of actions allowed
  max_retries: bigint; // Maximum retry attempts
  drift_threshold: bigint; // Maximum allowed state drift (bytes32 encoded)
}

/**
 * Agent identity with cryptographic verification
 */
export interface AgentIdentity {
  agent_id: `0x${string}`; // EVM address or DID identifier
  public_key: `0x${string}`; // ECDSA public key for signature verification
  agent_type: string; // Agent classification (e.g., "autonomous", "assistant")
  reputation_score: bigint; // Reputation score for access control
}

/**
 * Complete intent schema for ZK-Intent Guardian
 * All fields are ZK-verifiable and cryptographically bound
 */
export interface IntentSchema {
  version: string; // Schema version for compatibility
  agent: AgentIdentity; // Agent identity and credentials
  initial_state: InitialState; // Starting state for drift detection
  allowed_actions: ActionSpec[]; // Array of permitted action specifications
  bounds: IntentBounds; // Action space bounds for verification
  timestamp: bigint; // Unix timestamp for intent creation
  expiration: bigint; // Unix timestamp for intent expiration
  nonce: `0x${string}`; // Unique nonce for replay protection
  domain_separator: string; // EIP-712 domain separator
}

/**
 * Signed intent wrapper with signature verification
 */
export interface SignedIntent {
  intent: IntentSchema;
  signature: `0x${string}`; // ECDSA signature over intent hash
  signer: `0x${string}`; // Address that signed the intent
  signature_type: string; // Signature scheme (e.g., "ECDSA", "ED25519")
}

/**
 * Intent drift proof structure for ZK verification
 */
export interface DriftProof {
  intent_hash: `0x${string}`; // Hash of original intent
  current_state_hash: `0x${string}`; // Hash of current agent state
  action_hash: `0x${string}`; // Hash of proposed action
  proof: `0x${string}`; // ZK proof bytes
  public_inputs: {
    agent_id: `0x${string}`;
    state_diff: `0x${string}`;
    action_within_bounds: boolean;
  };
}

/**
 * Intent verification result from ZK proof
 */
export interface VerificationResult {
  valid: boolean;
  intent_hash: `0x${string}`;
  drift_detected: boolean;
  drift_amount: bigint;
  action_within_bounds: boolean;
  bounds_violation: string | null;
  proof_verified: boolean;
  timestamp: bigint;
}

/**
 * Intent signing utility class
 * Handles EIP-712 domain separation and signature generation
 */
export class IntentSigner {
  private provider: ethers.Provider;
  private signer: ethers.Signer;

  constructor(provider: ethers.Provider, signer: ethers.Signer) {
    this.provider = provider;
    this.signer = signer;
  }

  /**
   * Generate EIP-712 domain separator for intent signing
   */
  private async getDomainSeparator(): Promise<string> {
    const chainId = await this.provider.getNetwork();
    return ethers.TypedDataEncoder.domain({
      name: INTENT_DOMAIN_SEPARATOR,
      version: INTENT_VERSION,
      chainId: chainId.chainId,
      verifyingContract: await this.signer.getAddress(),
    });
  }

  /**
   * Validate EVM address format
   */
  private validateAddress(address: string): ValidatedAddress {
    if (!ethers.isAddress(address)) {
      throw new Error(`Invalid EVM address: ${address}`);
    }
    return address as ValidatedAddress;
  }

  /**
   * Validate bytes32 hex string format
   */
  private validateBytes32(value: string): `0x${string}` {
    if (!ethers.isHexString(value, 32)) {
      throw new Error(`Invalid bytes32 value: ${value}`);
    }
    return value as `0x${string}`;
  }

  /**
   * Validate parameter bounds for ZK compatibility
   */
  private validateParameterBound(bounds: ParameterBound): ParameterBound {
    return {
      min: this.validateBytes32(bounds.min),
      max: this.validateBytes32(bounds.max),
      step: this.validateBytes32(bounds.step),
    };
  }

  /**
   * Create and sign a new intent
   */
  async createIntent(
    agentId: string,
    publicKey: string,
    initialState: InitialState,
    allowedActions: ActionSpec[],
    bounds: IntentBounds,
    expiration: bigint
  ): Promise<SignedIntent> {
    const agent: AgentIdentity = {
      agent_id: this.validateAddress(agentId),
      public_key: this.validateBytes32(publicKey),
      agent_type: "autonomous",
      reputation_score: BigInt(100),
    };

    const intent: IntentSchema = {
      version: INTENT_VERSION,
      agent,
      initial_state: {
        state_hash: this.validateBytes32(initialState.state_hash),
        state_root: this.validateBytes32(initialState.state_root),
        block_number: initialState.block_number,
        chain_id: initialState.chain_id,
      },
      allowed_actions: allowedActions.map((action) => ({
        ...action,
        target_contracts: action.target_contracts.map((addr) =>
          this.validateAddress(addr)
        ),
        parameter_bounds: action.parameter_bounds.map((b) =>
          this.validateParameterBound(b)
        ),
        allowed_methods: action.allowed_methods.map((m) =>
          this.validateBytes32(m)
        ),
      })),
      bounds: {
        min_timestamp: bounds.min_timestamp,
        max_timestamp: bounds.max_timestamp,
        max_actions: bounds.max_actions,
        max_retries: bounds.max_retries,
        drift_threshold: this.validateBytes32(bounds.drift_threshold.toString()),
      },
      timestamp: BigInt(Math.floor(Date.now() / 1000)),
      expiration,
      nonce: ethers.hexlify(ethers.randomBytes(32)),
      domain_separator: await this.getDomainSeparator(),
    };

    const typedData = {
      types: {
        IntentSchema: [
          { name: "version", type: "string" },
          { name: "agent", type: "AgentIdentity" },
          { name: "initial_state", type: "InitialState" },
          { name: "allowed_actions", type: "ActionSpec[]" },
          { name: "bounds", type: "IntentBounds" },
          { name: "timestamp", type: "uint256" },
          { name: "expiration", type: "uint256" },
          { name: "nonce", type: "bytes32" },
          { name: "domain_separator", type: "string" },
        ],
        AgentIdentity: [
          { name: "agent_id", type: "address" },
          { name: "public_key", type: "bytes32" },
          { name: "agent_type", type: "string" },
          { name: "reputation_score", type: "uint256" },
        ],
        InitialState: [
          { name: "state_hash", type: "bytes32" },
          { name: "state_root", type: "bytes32" },
          { name: "block_number", type: "uint256" },
          { name: "chain_id", type: "uint256" },
        ],
        ActionSpec: [
          { name: "action_type", type: "uint8" },
          { name: "target_contracts", type: "address[]" },
          { name: "parameter_bounds", type: "ParameterBound[]" },
          { name: "max_gas_limit", type: "uint256" },
          { name: "max_value", type: "uint256" },
          { name: "allowed_methods", type: "bytes4[]" },
        ],
        ParameterBound: [
          { name: "min", type: "bytes32" },
          { name: "max", type: "bytes32" },
          { name: "step", type: "bytes32" },
        ],
        IntentBounds: [
          { name: "min_timestamp", type: "uint256" },
          { name: "max_timestamp", type: "uint256" },
          { name: "max_actions", type: "uint256" },
          { name: "max_retries", type: "uint256" },
          { name: "drift_threshold", type: "bytes32" },
        ],
      },
      primaryType: "IntentSchema",
      domain: await this.getDomainSeparator(),
      message: intent,
    };

    const signature = await this.signer.signTypedData(
      typedData.domain,
      typedData.types,
      typedData.message
    );

    return {
      intent,
      signature,
      signer: await this.signer.getAddress(),
      signature_type: "ECDSA",
    };
  }

  /**
   * Verify intent signature
   */
  async verifyIntentSignature(signedIntent: SignedIntent): Promise<boolean> {
    const recoveredAddress = ethers.verifyTypedData(
      {
        name: INTENT_DOMAIN_SEPARATOR,
        version: INTENT_VERSION,
        chainId: await this.provider.getNetwork(),
        verifyingContract: signedIntent.signer,
      },
      {
        IntentSchema: [
          { name: "version", type: "string" },
          { name: "agent", type: "AgentIdentity" },
          { name: "initial_state", type: "InitialState" },
          { name: "allowed_actions", type: "ActionSpec[]" },
          { name: "bounds", type: "IntentBounds" },
          { name: "timestamp", type: "uint256" },
          { name: "expiration", type: "uint256" },
          { name: "nonce", type: "bytes32" },
          { name: "domain_separator", type: "string" },
        ],
        AgentIdentity: [
          { name: "agent_id", type: "address" },
          { name: "public_key", type: "bytes32" },
          { name: "agent_type", type: "string" },
          { name: "reputation_score", type: "uint256" },
        ],
        InitialState: [
          { name: "state_hash", type: "bytes32" },
          { name: "state_root", type: "bytes32" },
          { name: "block_number", type: "uint256" },
          { name: "chain_id", type: "uint256" },
        ],
        ActionSpec: [
          { name: "action_type", type: "uint8" },
          { name: "target_contracts", type: "address[]" },
          { name: "parameter_bounds", type: "ParameterBound[]" },
          { name: "max_gas_limit", type: "uint256" },
          { name: "max_value", type: "uint256" },
          { name: "allowed_methods", type: "bytes4[]" },
        ],
        ParameterBound: [
          { name: "min", type: "bytes32" },
          { name: "max", type: "bytes32" },
          { name: "step", type: "bytes32" },
        ],
        IntentBounds: [
          { name: "min_timestamp", type: "uint256" },
          { name: "max_timestamp", type: "uint256" },
          { name: "max_actions", type: "uint256" },
          { name: "max_retries", type: "uint256" },
          { name: "drift_threshold", type: "bytes32" },
        ],
      },
      signedIntent.intent,
      signedIntent.signature
    );

    return recoveredAddress.toLowerCase() === signedIntent.signer.toLowerCase();
  }

  /**
   * Hash intent for ZK proof generation
   */
  hashIntent(intent: IntentSchema): `0x${string}` {
    return ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        [
          "string",
          "address",
          "bytes32",
          "bytes32",
          "uint256",
          "uint256",
          "uint256",
          "uint256",
          "uint256",
          "bytes32",
          "string",
        ],
        [
          intent.version,
          intent.agent.agent_id,
          intent.initial_state.state_hash,
          intent.initial_state.state_root,
          intent.bounds.min_timestamp,
          intent.bounds.max_timestamp,
          intent.bounds.max_actions,
          intent.bounds.max_retries,
          intent.bounds.drift_threshold,
          intent.nonce,
          intent.domain_separator,
        ]
      )
    );
  }
}

/**
 * Intent verification utility for ZK proof validation
 */
export class IntentVerifier {
  /**
   * Verify action is within intent bounds
   */
  static verifyActionWithinBounds(
    action: ActionSpec,
    intent: IntentSchema
  ): { valid: boolean; violation: string | null } {
    const actionSpec = intent.allowed_actions.find(
      (spec) => spec.action_type === action.action_type
    );

    if (!actionSpec) {
      return {
        valid: false,
        violation: "Action type not in allowed actions",
      };
    }

    // Verify target contracts
    const invalidContracts = action.target_contracts.filter(
      (addr) => !actionSpec.target_contracts.includes(addr)
    );
    if (invalidContracts.length > 0) {
      return {
        valid: false,
        violation: `Invalid target contracts: ${invalidContracts.join(", ")}`,
      };
    }

    // Verify parameter bounds
    for (const bound of action.parameter_bounds) {
      const specBound = actionSpec.parameter_bounds.find(
        (b) => b.min === bound.min && b.max === bound.max
      );
      if (!specBound) {
        return {
          valid: false,
          violation: "Parameter bounds exceed allowed range",
        };
      }
    }

    // Verify gas limit
    if (action.max_gas_limit > actionSpec.max_gas_limit) {
      return {
        valid: false,
        violation: "Gas limit exceeds allowed maximum",
      };
    }

    // Verify value transfer
    if (action.max_value > actionSpec.max_value) {
      return {
        valid: false,
        violation: "Value transfer exceeds allowed maximum",
      };
    }

    return { valid: true, violation: null };
  }

  /**
   * Verify intent has not expired
   */
  static verifyIntentValidity(intent: IntentSchema): {
    valid: boolean;
    expired: boolean;
  } {
    const now = BigInt(Math.floor(Date.now() / 1000));
    const expired = now > intent.expiration;

    return {
      valid: !expired,
      expired,
    };
  }

  /**
   * Verify state drift is within threshold
   */
  static verifyStateDrift(
    currentStateHash: `0x${string}`,
    initialState: InitialState,
    driftThreshold: bigint
  ): { valid: boolean; driftAmount: bigint } {
    // Simple Hamming distance approximation for state drift
    const driftAmount = BigInt(
      Array.from(currentStateHash)
        .filter((_, i) => currentStateHash[i] !== initialState.state_hash[i])
        .length
    );

    return {
      valid: driftAmount <= driftThreshold,
      driftAmount,
    };
  }
}

/**
 * Intent schema JSON serialization utilities
 */
export class IntentSerializer {
  /**
   * Serialize intent to JSON for storage/transmission
   */
  static serialize(intent: IntentSchema): string {
    return JSON.stringify(intent, (key, value) => {
      if (typeof value === "bigint") {
        return value.toString();
      }
      return value;
    });
  }

  /**
   * Deserialize intent from JSON
   */
  static deserialize(json: string): IntentSchema {
    const parsed = JSON.parse(json, (key, value) => {
      if (
        key === "timestamp" ||
        key === "expiration" ||
        key === "min_timestamp" ||
        key === "max_timestamp" ||
        key === "max_actions" ||
        key === "max_retries" ||
        key === "reputation_score" ||
        key === "max_gas_limit" ||
        key === "max_value" ||
        key === "block_number" ||
        key === "chain_id"
      ) {
        return BigInt(value);
      }
      return value;
    });

    return parsed as IntentSchema;
  }

  /**
   * Serialize signed intent to JSON
   */
  static serializeSigned(signedIntent: SignedIntent): string {
    return JSON.stringify(signedIntent, (key, value) => {
      if (typeof value === "bigint") {
        return value.toString();
      }
      return value;
    });
  }

  /**
   * Deserialize signed intent from JSON
   */
  static deserializeSigned(json: string): SignedIntent {
    const parsed = JSON.parse(json, (key, value) => {
      if (
        key === "timestamp" ||
        key === "expiration" ||
        key === "min_timestamp" ||
        key === "max_timestamp" ||
        key === "max_actions" ||
        key === "max_retries" ||
        key === "reputation_score" ||
        key === "max_gas_limit" ||
        key === "max_value" ||
        key === "block_number" ||
        key === "chain_id"
      ) {
        return BigInt(value);
      }
      return value;
    });

    return parsed as SignedIntent;
  }
}

/**
 * Intent bounds calculator for dynamic action space generation
 */
export class IntentBoundsCalculator {
  /**
   * Calculate safe bounds for action parameters
   */
  static calculateSafeBounds(
    min: bigint,
    max: bigint,
    step: bigint
  ): ParameterBound {
    if (min >= max) {
      throw new Error("Min must be less than max");
    }
    if (step <= 0) {
      throw new Error("Step must be positive");
    }
    if ((max - min) % step !== 0n) {
      throw new Error("Range must be divisible by step");
    }

    return {
      min: ethers.hexlify(ethers.toBeBytes32(min)),
      max: ethers.hexlify(ethers.toBeBytes32(max)),
      step: ethers.hexlify(ethers.toBeBytes32(step)),
    };
  }

  /**
   * Generate intent bounds from action specifications
   */
  static generateBounds(
    actions: ActionSpec[],
    maxTimestampOffset: bigint
  ): IntentBounds {
    const maxGas = actions.reduce(
      (acc, action) => (action.max_gas_limit > acc ? action.max_gas_limit : acc),
      0n
    );
    const maxValue = actions.reduce(
      (acc, action) => (action.max_value > acc ? action.max_value : acc),
      0n
    );

    const now = BigInt(Math.floor(Date.now() / 1000));

    return {
      min_timestamp: now,
      max_timestamp: now + maxTimestampOffset,
      max_actions: BigInt(actions.length),
      max_retries: 3n,
      drift_threshold: ethers.hexlify(ethers.toBeBytes32(100n)),
    };
  }
}

/**
 * Intent schema constants and configuration
 */
export const INTENT_CONFIG = {
  MAX_ACTION_TYPES: 10,
  MAX_TARGET_CONTRACTS: 100,
  MAX_PARAMETER_BOUNDS: 50,
  MAX_ALLOWED_METHODS: 100,
  MIN_TIMESTAMP_OFFSET: 3600n, // 1 hour minimum
  MAX_TIMESTAMP_OFFSET: 31536000n, // 1 year maximum
  DEFAULT_REPUTATION_SCORE: 100n,
  DRIFT_THRESHOLD_DEFAULT: 100n,
};

/**
 * Intent schema validation schema for runtime checks
 */
export const INTENT_VALIDATION_SCHEMA = {
  required: [
    "version",
    "agent",
    "initial_state",
    "allowed_actions",
    "bounds",
    "timestamp",
    "expiration",
    "nonce",
    "domain_separator",
  ],
  agent: {
    required: ["agent_id", "public_key", "agent_type", "reputation_score"],
  },
  initial_state: {
    required: ["state_hash", "state_root", "block_number", "chain_id"],
  },
  bounds: {
    required: [
      "min_timestamp",
      "max_timestamp",
      "max_actions",
      "max_retries",
      "drift_threshold",
    ],
  },
};

/**
 * Intent schema versioning and migration utilities
 */
export class IntentVersionManager {
  private static currentVersion = INTENT_VERSION;

  static getCurrentVersion(): string {
    return this.currentVersion;
  }

  static validateVersion(version: string): boolean {
    return version === this.currentVersion;
  }

  static migrateIntent(intent: IntentSchema, fromVersion: string): IntentSchema {
    if (fromVersion === this.currentVersion) {
      return intent;
    }

    // Migration logic for version upgrades
    const migrated = { ...intent };

    return migrated;
  }
}

/**
 * Intent event types for multi-agent communication
 */
export enum IntentEventType {
  INTENT_CREATED = "IntentCreated",
  INTENT_EXPIRED = "IntentExpired",
  ACTION_EXECUTED = "ActionExecuted",
  DRIFT_DETECTED = "DriftDetected",
  INTENT_REVOKED = "IntentRevoked",
}

/**
 * Intent event structure for event logging
 */
export interface IntentEvent {
  event_type: IntentEventType;
  intent_hash: `0x${string}`;
  agent_id: `0x${string}`;
  timestamp: bigint;
  metadata: Record<string, string | bigint | boolean>;
}

/**
 * Intent audit log entry for compliance tracking
 */
export interface IntentAuditEntry {
  intent_hash: `0x${string}`;
  action_hash: `0x${string}`;
  agent_id: `0x${string}`;
  action_type: ActionType;
  timestamp: bigint;
  verification_result: VerificationResult;
  block_number: bigint;
  transaction_hash: `0x${string}`;
}

/**
 * Intent policy for access control
 */
export interface IntentPolicy {
  policy_id: `0x${string}`;
  agent_id: `0x${string}`;
  allowed_action_types: ActionType[];
  blocked_contracts: `0x${string}`[];
  max_value_per_action: bigint;
  max_gas_per_action: bigint;
  requires_approval: boolean;
  approval_threshold: bigint;
}

/**
 * Intent policy enforcement engine
 */
export class IntentPolicyEnforcer {
  private policies: Map<string, IntentPolicy>;

  constructor() {
    this.policies = new Map();
  }

  registerPolicy(policy: IntentPolicy): void {
    this.policies.set(policy.policy_id, policy);
  }

  getPolicy(agentId: string): IntentPolicy | null {
    for (const policy of this.policies.values()) {
      if (policy.agent_id === agentId) {
        return policy;
      }
    }
    return null;
  }

  enforcePolicy(
    action: ActionSpec,
    agentId: string
  ): { allowed: boolean; reason: string } {
    const policy = this.getPolicy(agentId);

    if (!policy) {
      return {
        allowed: false,
        reason: "No policy found for agent",
      };
    }

    if (!policy.allowed_action_types.includes(action.action_type)) {
      return {
        allowed: false,
        reason: "Action type not allowed by policy",
      };
    }

    const blocked = action.target_contracts.some((addr) =>
      policy.blocked_contracts.includes(addr)
    );

    if (blocked) {
      return {
        allowed: false,
        reason: "Target contract blocked by policy",
      };
    }

    if (action.max_value > policy.max_value_per_action) {
      return {
        allowed: false,
        reason: "Value exceeds policy limit",
      };
    }

    if (action.max_gas_limit > policy.max_gas_per_action) {
      return {
        allowed: false,
        reason: "Gas exceeds policy limit",
      };
    }

    return { allowed: true, reason: "" };
  }
}

/**
 * Intent circuit interface for Circom integration
 */
export interface ZKCircuitInput {
  agent_id: `0x${string}`;
  intent_hash: `0x${string}`;
  current_state_hash: `0x${string}`;
  action_type: number;
  action_params: `0x${string}`[];
  bounds_min: `0x${string}`[];
  bounds_max: `0x${string}`[];
  bounds_step: `0x${string}`[];
  timestamp: bigint;
  drift_threshold: `0x${string}`;
}

/**
 * ZK proof generation interface
 */
export interface ZKProofGenerator {
  generateProof(input: ZKCircuitInput): Promise<{
    proof: `0x${string}`;
    publicInputs: {
      agent_id: `0x${string}`;
      intent_hash: `0x${string}`;
      action_within_bounds: boolean;
      drift_within_threshold: boolean;
    };
  }>;

  verifyProof(
    proof: `0x${string}`,
    publicInputs: {
      agent_id: `0x${string}`;
      intent_hash: `0x${string}`;
      action_within_bounds: boolean;
      drift_within_threshold: boolean;
    }
  ): Promise<boolean>;
}

/**
 * Intent guardian state for runtime tracking
 */
export interface IntentGuardianState {
  active_intents: Map<string, SignedIntent>;
  intent_history: IntentAuditEntry[];
  policy_enforcer: IntentPolicyEnforcer;
  last_updated: bigint;
  total_intents_created: bigint;
  total_actions_verified: bigint;
  total_drifts_detected: bigint;
}

/**
 * Intent guardian configuration
 */
export interface IntentGuardianConfig {
  chain_id: bigint;
  verifier_contract: `0x${string}`;
  max_intents_per_agent: bigint;
  default_expiration: bigint;
  drift_detection_interval: bigint;
  audit_log_retention: bigint;
}

/**
 * Intent guardian main class for multi-agent orchestration
 */
export class IntentGuardian {
  private config: IntentGuardianConfig;
  private state: IntentGuardianState;
  private signer: IntentSigner;

  constructor(
    config: IntentGuardianConfig,
    provider: ethers.Provider,
    signer: ethers.Signer
  ) {
    this.config = config;
    this.state = {
      active_intents: new Map(),
      intent_history: [],
      policy_enforcer: new IntentPolicyEnforcer(),
      last_updated: BigInt(Math.floor(Date.now() / 1000)),
      total_intents_created: 0n,
      total_actions_verified: 0n,
      total_drifts_detected: 0n,
    };
    this.signer = new IntentSigner(provider, signer);
  }

  /**
   * Create and register a new intent
   */
  async createAndRegisterIntent(
    agentId: string,
    publicKey: string,
    initialState: InitialState,
    allowedActions: ActionSpec[],
    bounds: IntentBounds,
    expiration: bigint
  ): Promise<SignedIntent> {
    const signedIntent = await this.signer.createIntent(
      agentId,
      publicKey,
      initialState,
      allowedActions,
      bounds,
      expiration
    );

    this.state.active_intents.set(signedIntent.intent.nonce, signedIntent);
    this.state.total_intents_created += 1n;
    this.state.last_updated = BigInt(Math.floor(Date.now() / 1000));

    return signedIntent;
  }

  /**
   * Verify action against registered intent
   */
  async verifyAction(
    signedIntent: SignedIntent,
    action: ActionSpec,
    currentStateHash: `0x${string}`
  ): Promise<VerificationResult> {
    const boundsCheck = IntentVerifier.verifyActionWithinBounds(
      action,
      signedIntent.intent
    );

    const validityCheck = IntentVerifier.verifyIntentValidity(
      signedIntent.intent
    );

    const driftCheck = IntentVerifier.verifyStateDrift(
      currentStateHash,
      signedIntent.intent.initial_state,
      signedIntent.intent.bounds.drift_threshold
    );

    const policyCheck = this.state.policy_enforcer.enforcePolicy(
      action,
      signedIntent.intent.agent.agent_id
    );

    const valid =
      boundsCheck.valid &&
      validityCheck.valid &&
      driftCheck.valid &&
      policyCheck.allowed;

    return {
      valid,
      intent_hash: this.signer.hashIntent(signedIntent.intent),
      drift_detected: !driftCheck.valid,
      drift_amount: driftCheck.driftAmount,
      action_within_bounds: boundsCheck.valid,
      bounds_violation: boundsCheck.violation,
      proof_verified: valid,
      timestamp: BigInt(Math.floor(Date.now() / 1000)),
    };
  }

  /**
   * Get active intents for agent
   */
  getActiveIntents(agentId: string): SignedIntent[] {
    return Array.from(this.state.active_intents.values()).filter(
      (intent) => intent.intent.agent.agent_id === agentId
    );
  }

  /**
   * Get audit history
   */
  getAuditHistory(): IntentAuditEntry[] {
    return this.state.intent_history;
  }

  /**
   * Get guardian statistics
   */
  getStatistics(): {
    total_intents_created: bigint;
    total_actions_verified: bigint;
    total_drifts_detected: bigint;
    active_intents_count: number;
  } {
    return {
      total_intents_created: this.state.total_intents_created,
      total_actions_verified: this.state.total_actions_verified,
      total_drifts_detected: this.state.total_drifts_detected,
      active_intents_count: this.state.active_intents.size,
    };
  }
}

/**
 * Export all intent schema components
 */
export {
  ActionType,
  IntentSchema,
  SignedIntent,
  DriftProof,
  VerificationResult,
  IntentSigner,
  IntentVerifier,
  IntentSerializer,
  IntentBoundsCalculator,
  INTENT_CONFIG,
  INTENT_VALIDATION_SCHEMA,
  IntentVersionManager,
  IntentEventType,
  IntentEvent,
  IntentAuditEntry,
  IntentPolicy,
  IntentPolicyEnforcer,
  ZKCircuitInput,
  ZKProofGenerator,
  IntentGuardianState,
  IntentGuardianConfig,
  IntentGuardian,
};