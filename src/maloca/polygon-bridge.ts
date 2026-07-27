import {
	Contract,
	ContractFactory,
	Interface,
	JsonRpcProvider,
	Wallet,
} from "ethers";

// ─── ANCHOR & CONFIG INTERFACES ───────────────────────────────────────────

export interface Anchor {
	merkleRoot: string; // 32-byte hex string (0x...)
	cid: string; // IPFS/Content Identifier
	timestamp?: number;
}

export interface PolygonBridgeConfig {
	rpcUrl: string; // Polygon Mumbai/Amoy testnet
	contractAddress: string; // EvidentiaAnchor smart contract
	privateKey?: string; // Opcional: wallet del nodo
}

export interface PolygonBridge {
	submitAnchor(anchor: Anchor): Promise<string>; // returns txHash
	getAnchor(txHash: string): Promise<Anchor | null>;
	verifyOnChain(
		merkleRoot: string,
		proof: string[],
		leaf?: string,
	): Promise<boolean>;
	getLastAnchorBlock(): Promise<number>;
	getQueue(): Anchor[];
	clearQueue(): void;
	flushQueue(): Promise<string | null>;
}

// ─── EMBEDDED CONTRACT METADATA ──────────────────────────────────────────

export const EVIDENTIA_ANCHOR_ABI = [
	"event AnchorSubmitted(bytes32 indexed merkleRoot, string cid, uint256 timestamp)",
	"function anchors(bytes32) view returns (string cid, uint256 timestamp)",
	"function submitAnchor(bytes32 merkleRoot, string calldata cid) external",
	"function submitAnchors(bytes32[] calldata merkleRoots, string[] calldata cids) external",
	"function verifyProof(bytes32 merkleRoot, bytes32 leaf, bytes32[] calldata proof) external view returns (bool)",
];

export const EVIDENTIA_ANCHOR_BYTECODE =
	"6080604052348015600e575f5ffd5b50610d728061001c5f395ff3fe608060405234801561000f575f5ffd5b506004361061004a575f3560e01c80633d2fa6de1461004e5780639da7347c1461006a578063b01b6d531461009a578063f6a1a14b146100cb575b5f5ffd5b61006860048036038101906100639190610570565b6100e7565b005b610084600480360381019061007f9190610622565b6101b1565b60405161009191906106ad565b60405180910390f35b6100b460048036038101906100af91906106c6565b610286565b6040516100c2929190610779565b60405180910390f35b6100e560048036038101906100e091906107fc565b61032b565b005b604051806040016040528083838080601f0160208091040260200160405190810160405280939291908181526020018383808284375f81840152601f19601f820116905080830192505050505050508152602001428152505f5f8581526020019081526020015f205f820151815f0190816101629190610ab5565b5060208201518160010155905050827f07833cba3144cd16b692ac14ef1b6f77f743ee5519895d3a98e4aaf7637fe45d8383426040516101a493929190610bbe565b60405180910390a2505050565b5f5f5f5f8781526020019081526020015f2060010154036101d4575f905061027e565b5f8490505f5f90505b84849050811015610276575f8585838181106101fc576101fb610bee565b5b90506020020135905080831161023c57828160405160200161021f929190610c3b565b604051602081830303815290604052805190602001209250610268565b808360405160200161024f929190610c3b565b6040516020818303038152906040528051906020012092505b5080806001019150506101dd565b508581149150505b949350505050565b5f602052805f5260405f205f91509050805f0180546102a4906108d4565b80601f01602080910402602001604051908101604052809291908181526020018280546102d0906108d4565b801561031b5780601f106102f25761010080835404028352916020019161031b565b820191905f5260205f20905b8154815290600101906020018083116102fe57829003601f168201915b5050505050908060010154905082565b818190508484905014610373576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161036a90610cb0565b60405180910390fd5b5f5f90505b848490508110156104cd5760405180604001604052808484848181106103a1576103a0610bee565b5b90506020028101906103b39190610cda565b8080601f0160208091040260200160405190810160405280939291908181526020018383808284375f81840152601f19601f820116905080830192505050505050508152602001428152505f5f87878581811061041357610412610bee565b5b9050602002013581526020019081526020015f205f820151815f01908161043a9190610ab5565b506020820151816001015590505084848281811061045b5761045a610bee565b5b905060200201357f07833cba3144cd16b692ac14ef1b6f77f743ee5519895d3a98e4aaf7637fe45d84848481811061049657610495610bee565b5b90506020028101906104a89190610cda565b426040516104b893929190610bbe565b60405180910390a28080600101915050610378565b5050505050565b5f5ffd5b5f5ffd5b5f819050919050565b6104ee816104dc565b81146104f8575f5ffd5b50565b5f81359050610509816104e5565b92915050565b5f5ffd5b5f5ffd5b5f5ffd5b5f5f83601f8401126105305761052f61050f565b5b8235905067ffffffffffffffff81111561054d5761054c610513565b5b60208301915083600182028301111561056957610568610517565b5b9250929050565b5f5f5f60408486031215610587576105866104d4565b5b5f610594868287016104fb565b935050602084013567ffffffffffffffff8111156105b5576105b46104d8565b5b6105c18682870161051b565b92509250509250925092565b5f5f83601f8401126105e2576105e161050f565b5b8235905067ffffffffffffffff8111156105ff576105fe610513565b5b60208301915083602082028301111561061b5761061a610517565b5b9250929050565b5f5f5f5f6060858703121561063a576106396104d4565b5b5f610647878288016104fb565b935050604085013567ffffffffffffffff811115610679576106786104d8565b5b610685878288016105cd565b925092505092959194509250565b5f8115159050919050565b6106a781610693565b82525050565b5f6020820190506106c05f83018461069e565b92915050565b5f602082840312156106db576106da6104d4565b5b5f6106e8848285016104fb565b91505092915050565b5f81519050919050565b5f82825260208201905092915050565b8281835e5f83830152505050565b5f601f19601f8301169050919050565b5f610733826106f1565b61073d81856106fb565b935061074d81856020860161070b565b61075681610719565b840191505092915050565b5f819050919050565b61077381610761565b82525050565b5f6040820190508181035f8301526107918185610729565b90506107a0602083018461076a565b9392505050565b5f5f83601f8401126107bc576107bb61050f565b5b8235905067ffffffffffffffff8111156107d9576107d8610513565b5b6020830191508360208202830111156107f5576107f4610517565b5b9250929050565b5f5f5f5f60408587031215610814576108136104d4565b5b5f85013567ffffffffffffffff811115610831576108306104d8565b5b61083d878288016105cd565b9450945050602085013567ffffffffffffffff8111156108605761085f6104d8565b5b61086c878288016107a7565b925092505092959194509250565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602260045260245ffd5b5f60028204905060018216806108eb57607f821691505b6020821081036108fe576108fd6108a7565b5b50919050565b5f819050815f5260205f209050919050565b5f6020601f8301049050919050565b5f82821b905092915050565b5f600883026109607fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82610925565b61096a8683610925565b95508019841693508086168417925050509392505050565b5f819050919050565b5f6109a56109a061099b84610761565b610982565b610761565b9050919050565b5f819050919050565b6109be8361098b565b6109d26109ca826109ac565b848454610931565b825550505050565b5f5f905090565b6109e96109da565b6109f48184846109b5565b505050565b5f5b82811015610a1a57610a0f5f8284016109e1565b6001810190506109fb565b505050565b601f821115610a6d5782821115610a6c57610a3981610904565b610a4283610916565b610a4b85610916565b6020861015610a58575f90505b808301610a67828403826109f9565b505050505b5b505050565b5f82821c905092915050565b5f610a8d5f1984600802610a72565b1980831691505092915050565b5f610aa58383610a7e565b9150826002028217905092915050565b610abe826106f1565b67ffffffffffffffff811115610ad757610ad661087a565b5b610ae182546108d4565b610aec828285610a1f565b5f60209050601f831160018114610b1d575f8415610b0b578287015190505b610b158582610a9a565b865550610b7c565b601f198416610b2b86610904565b5f5b82811015610b5257848901518255600182019150602085019450602081019050610b2d565b86831015610b6f5784890151610b6b601f891682610a7e565b8355505b6001600288020188555050505b505050505050565b828183375f83830152505050565b5f610b9d83856106fb565b9350610baa838584610b84565b610bb383610719565b840190509392505050565b5f6040820190508181035f830152610bd7818587610b92565b9050610be6602083018461076a565b949350505050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52603260045260245ffd5b5f819050919050565b610c35610c30826104dc565b610c1b565b82525050565b5f610c468285610c24565b602082019150610c568284610c24565b6020820191508190509392505050565b7f4c656e677468206d69736d6174636800000000000000000000000000000000005f82015250565b5f610c9a600f836106fb565b9150610ca582610c66565b602082019050919050565b5f6020820190508181035f830152610cc781610c8e565b9050919050565b5f5ffd5b5f5ffd5b5f5ffd5b5f5f83356001602003843603038112610cf657610cf5610cce565b5b80840192508235915067ffffffffffffffff821115610d1857610d17610cd2565b5b602083019250600182023603831315610d3457610d33610cd6565b5b50925092905056fea264697066735822122013ec0094c28329a28c56d8464436cda8ddcaa624fbccab6a1d017cf97d31d0c064736f6c63430008240033";

// ─── POLYGON BRIDGE IMPLEMENTATION ────────────────────────────────────────

export class PolygonBridgeImpl implements PolygonBridge {
	private readonly config: PolygonBridgeConfig;
	private provider: JsonRpcProvider | null = null;
	private wallet: Wallet | null = null;
	private contract: Contract | null = null;
	private offlineQueue: Anchor[] = [];

	constructor(config: PolygonBridgeConfig) {
		this.config = config;
		if (config.rpcUrl) {
			this.provider = new JsonRpcProvider(config.rpcUrl);
			if (config.privateKey) {
				this.wallet = new Wallet(config.privateKey, this.provider);
			}
			if (config.contractAddress) {
				const signerOrProvider = this.wallet || this.provider;
				this.contract = new Contract(
					config.contractAddress,
					EVIDENTIA_ANCHOR_ABI,
					signerOrProvider,
				);
			}
		}
	}

	/**
	 * Envía un anchor individual (merkleRoot + cid) a Polygon.
	 * Si la red o el proveedor no están disponibles, se encola localmente y lanza un error.
	 */
	async submitAnchor(anchor: Anchor): Promise<string> {
		if (!this.provider || !this.contract) {
			this.offlineQueue.push(anchor);
			throw new Error(
				"Polygon provider or contract not configured. Anchor queued.",
			);
		}

		try {
			// Enviar la transacción llamando a la función submitAnchor en Solidity
			const tx = await this.contract.submitAnchor(
				anchor.merkleRoot,
				anchor.cid,
			);
			const receipt = await tx.wait();
			if (!receipt) {
				throw new Error("Failed to retrieve transaction receipt");
			}
			return receipt.hash;
		} catch (error) {
			this.offlineQueue.push(anchor);
			throw error;
		}
	}

	/**
	 * Obtiene los detalles de un Anchor basándose en el hash de transacción o logs.
	 */
	async getAnchor(txHash: string): Promise<Anchor | null> {
		if (!this.provider) return null;

		try {
			const tx = await this.provider.getTransaction(txHash);
			if (!tx) return null;

			const iface = new Interface(EVIDENTIA_ANCHOR_ABI);

			// Intentar parsear los datos de entrada de la transacción
			try {
				const parsed = iface.parseTransaction({
					data: tx.data,
					value: tx.value,
				});
				if (parsed) {
					if (parsed.name === "submitAnchor") {
						return {
							merkleRoot: parsed.args[0],
							cid: parsed.args[1],
						};
					}
					if (parsed.name === "submitAnchors") {
						// Si fue batch, retornamos el primer anchor
						const roots = parsed.args[0] as string[];
						const cids = parsed.args[1] as string[];
						if (roots.length > 0) {
							return {
								merkleRoot: roots[0],
								cid: cids[0],
							};
						}
					}
				}
			} catch (err) {
				// Fallback a logs de la transacción
			}

			// Intentar recuperar desde logs del recibo
			const receipt = await this.provider.getTransactionReceipt(txHash);
			if (receipt) {
				for (const log of receipt.logs) {
					try {
						const parsedLog = iface.parseLog(log);
						if (parsedLog && parsedLog.name === "AnchorSubmitted") {
							return {
								merkleRoot: parsedLog.args[0],
								cid: parsedLog.args[1],
							};
						}
					} catch (logErr) {
						// Ignorar logs que no pertenezcan al contrato
					}
				}
			}
		} catch (err) {
			// Capturar cualquier error de red/rpc
		}

		return null;
	}

	/**
	 * Verifica un Merkle proof contra el root on-chain de Polygon.
	 */
	async verifyOnChain(
		merkleRoot: string,
		proof: string[],
		leaf?: string,
	): Promise<boolean> {
		if (!this.contract) {
			throw new Error("Polygon contract not configured.");
		}

		try {
			const leafHash = leaf || merkleRoot;
			return await this.contract.verifyProof(merkleRoot, leafHash, proof);
		} catch (err) {
			return false;
		}
	}

	/**
	 * Obtiene el último bloque de Polygon.
	 */
	async getLastAnchorBlock(): Promise<number> {
		if (!this.provider) return 0;
		try {
			return await this.provider.getBlockNumber();
		} catch (err) {
			return 0;
		}
	}

	/**
	 * Retorna la cola de anchors fuera de línea.
	 */
	getQueue(): Anchor[] {
		return this.offlineQueue;
	}

	/**
	 * Vacía la cola.
	 */
	clearQueue(): void {
		this.offlineQueue = [];
	}

	/**
	 * Envía todos los anchors encolados en una sola transacción batch.
	 */
	async flushQueue(): Promise<string | null> {
		if (this.offlineQueue.length === 0) {
			return null;
		}

		if (!this.provider || !this.contract) {
			throw new Error(
				"Polygon provider or contract not configured for flushing queue.",
			);
		}

		const batch = [...this.offlineQueue];
		const merkleRoots = batch.map((a) => a.merkleRoot);
		const cids = batch.map((a) => a.cid);

		try {
			const tx = await this.contract.submitAnchors(merkleRoots, cids);
			const receipt = await tx.wait();
			if (!receipt) {
				throw new Error(
					"Failed to retrieve transaction receipt for batch flush",
				);
			}
			// Limpiar la cola en caso de éxito
			this.offlineQueue = [];
			return receipt.hash;
		} catch (error) {
			throw error;
		}
	}

	/**
	 * Despliega programáticamente una instancia del contrato EvidentiaAnchor.
	 */
	static async deploy(rpcUrl: string, privateKey: string): Promise<string> {
		const provider = new JsonRpcProvider(rpcUrl);
		const wallet = new Wallet(privateKey, provider);
		const factory = new ContractFactory(
			EVIDENTIA_ANCHOR_ABI,
			EVIDENTIA_ANCHOR_BYTECODE,
			wallet,
		);
		const contract = await factory.deploy();
		await contract.waitForDeployment();
		const address = await contract.getAddress();
		return address;
	}
}
