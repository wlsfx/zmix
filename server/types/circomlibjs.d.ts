declare module 'circomlibjs' {
  export interface PoseidonField {
    toString(value: any): string;
  }

  export interface Poseidon {
    (inputs: bigint[]): any;
    F: PoseidonField;
  }

  export function buildPoseidon(): Promise<Poseidon>;
}
