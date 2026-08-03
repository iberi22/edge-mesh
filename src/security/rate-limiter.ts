export interface RateLimiterConfig {
	tokensPerInterval: number;
	intervalMs: number;
	maxTokens: number;
}

export class TokenBucketRateLimiter {
	private buckets: Map<string, { tokens: number; lastRefill: number }> =
		new Map();

	constructor(private config: RateLimiterConfig) {}

	consume(key: string, tokens = 1): boolean {
		const now = Date.now();
		let bucket = this.buckets.get(key);

		if (!bucket) {
			bucket = { tokens: this.config.maxTokens, lastRefill: now };
			this.buckets.set(key, bucket);
		} else {
			const elapsed = now - bucket.lastRefill;
			if (elapsed > 0) {
				const tokensToAdd =
					elapsed * (this.config.tokensPerInterval / this.config.intervalMs);
				bucket.tokens = Math.min(
					this.config.maxTokens,
					bucket.tokens + tokensToAdd,
				);
				bucket.lastRefill = now;
			}
		}

		if (bucket.tokens >= tokens) {
			bucket.tokens -= tokens;
			return true;
		}
		return false;
	}

	reset(key: string): void {
		this.buckets.delete(key);
	}
}
