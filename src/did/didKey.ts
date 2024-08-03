import { ec } from 'elliptic'
import bs58 from 'bs58'

export class DidKey {
  public keyPair: ec.KeyPair
  public did: string

  constructor() {
    const secp256k1 = new ec('secp256k1')
    this.keyPair = secp256k1.genKeyPair()
    const pub = this.keyPair.getPublic()
    const xhex = pub.getX().toBuffer().toString('hex')
    const yhex = pub.getY().toBuffer().toString('hex')

    const multicodec = `E701${parseInt(yhex.slice(-1), 16) % 2 == 1 ? '03' : '02'}`
    this.did = `did:key:z${bs58.encode(Buffer.from(`${multicodec}${xhex}`, 'hex'))}`
  }

  getPublicJwk(): JsonWebKey {
    const pub = this.keyPair.getPublic()
    return {
      kty: 'EC',
      crv: 'secp256k1',
      x: pub.getX().toBuffer().toString('base64url'),
      y: pub.getY().toBuffer().toString('base64url'),
    }
  }

  getPrivateJwk(): JsonWebKey {
    const pubJwk = this.getPublicJwk()
    return {
      ...pubJwk,
      d: this.keyPair.getPrivate().toBuffer().toString('base64url'),
    }
  }
}

export default DidKey
