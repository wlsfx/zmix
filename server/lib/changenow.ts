import axios from 'axios';

const CHANGENOW_API_BASE = 'https://api.changenow.io/v1';

// Note: In production, store API key in environment variable
// For now, ChangeNOW allows testing without API key (limited rate)
const API_KEY = process.env.CHANGENOW_API_KEY || '';

export interface Currency {
  ticker: string;
  name: string;
  image: string;
  hasExternalId: boolean;
  isFiat: boolean;
  featured: boolean;
  isStable: boolean;
  supportsFixedRate: boolean;
}

export interface MinAmountResponse {
  minAmount: number;
}

export interface EstimateResponse {
  estimatedAmount: number;
  transactionSpeedForecast: string;
  warningMessage?: string;
}

export interface CreateExchangeRequest {
  from: string;
  to: string;
  address: string;  // Recipient address (destination)
  amount: string;   // Amount to send (SOL)
  refundAddress: string;  // Refund address (SOL address)
  extraId?: string;
}

export interface CreateExchangeResponse {
  id: string;
  payinAddress: string;
  payoutAddress: string;
  fromCurrency: string;
  toCurrency: string;
  refundAddress: string;
  amount: number;
  amountExpectedFrom: number;
  amountExpectedTo: number;
  status: string;
}

export interface TransactionStatus {
  id: string;
  status: string;
  payinAddress: string;
  payoutAddress: string;
  fromCurrency: string;
  toCurrency: string;
  amountExpectedFrom: number;
  amountExpectedTo: number;
  payinHash?: string;
  payoutHash?: string;
  refundHash?: string;
  createdAt: string;
  updatedAt: string;
}

class ChangeNowClient {
  private apiKey: string;

  constructor(apiKey: string = '') {
    this.apiKey = apiKey;
  }

  /**
   * Get list of available currencies
   */
  async getCurrencies(activeOnly: boolean = true): Promise<Currency[]> {
    const params: Record<string, string> = {};
    if (activeOnly) params.active = 'true';
    if (this.apiKey) params.api_key = this.apiKey;

    const response = await axios.get(`${CHANGENOW_API_BASE}/currencies`, { params });
    return response.data;
  }

  /**
   * Get minimum exchange amount for a currency pair
   */
  async getMinAmount(from: string, to: string): Promise<number> {
    const params: Record<string, string> = {};
    if (this.apiKey) params.api_key = this.apiKey;

    const response = await axios.get(
      `${CHANGENOW_API_BASE}/min-amount/${from}_${to}`,
      { params }
    );
    return response.data.minAmount;
  }

  /**
   * Get estimated exchange amount
   */
  async getEstimate(from: string, to: string, amount: string): Promise<EstimateResponse> {
    const params: Record<string, string> = {};
    if (this.apiKey) params.api_key = this.apiKey;

    const response = await axios.get(
      `${CHANGENOW_API_BASE}/exchange-amount/${amount}/${from}_${to}`,
      { params }
    );
    return response.data;
  }

  /**
   * Create exchange transaction
   */
  async createExchange(request: CreateExchangeRequest): Promise<CreateExchangeResponse> {
    const url = this.apiKey 
      ? `${CHANGENOW_API_BASE}/transactions/${this.apiKey}`
      : `${CHANGENOW_API_BASE}/transactions`;

    const response = await axios.post(url, {
      from: request.from,
      to: request.to,
      address: request.address,
      amount: request.amount,
      refundAddress: request.refundAddress,
      extraId: request.extraId || ''
    });

    return response.data;
  }

  /**
   * Get transaction status
   */
  async getTransactionStatus(transactionId: string): Promise<TransactionStatus> {
    const url = this.apiKey
      ? `${CHANGENOW_API_BASE}/transactions/${transactionId}/${this.apiKey}`
      : `${CHANGENOW_API_BASE}/transactions/${transactionId}`;

    const response = await axios.get(url);
    return response.data;
  }

  /**
   * Check if SOL is supported
   */
  async verifySolSupport(): Promise<{ sol: boolean }> {
    const currencies = await this.getCurrencies(true);
    const tickers = currencies.map(c => c.ticker.toLowerCase());
    
    return {
      sol: tickers.includes('sol'),
    };
  }
}

export const changeNowClient = new ChangeNowClient(API_KEY);
