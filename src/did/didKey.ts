import { ec } from 'elliptic'

export class DidKey {
  public keyPair: ec.KeyPair

  constructor() {
    const secp256k1 = new ec('secp256k1')
    this.keyPair = secp256k1.genKeyPair()
  }
}

export default DidKey
