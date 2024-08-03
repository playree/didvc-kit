import { ec } from 'elliptic'
import bs58 from 'bs58'

export class DidKey {
  public keyPair: ec.KeyPair
  public did: string

  constructor(keyPair?: ec.KeyPair) {
    if (keyPair) {
      this.keyPair = keyPair
    } else {
      const secp256k1 = new ec('secp256k1')
      this.keyPair = secp256k1.genKeyPair()
    }

    const pub = this.keyPair.getPublic()
    const xhex = pub.getX().toBuffer().toString('hex')
    const yhex = pub.getY().toBuffer().toString('hex')

    const multicodec = 'e701'
    const pubkey = `${parseInt(yhex.slice(-1), 16) % 2 == 1 ? '03' : '02'}${xhex}`
    console.debug('hex:', multicodec, pubkey)

    this.did = `did:key:z${bs58.encode(Buffer.from(`${multicodec}${pubkey}`, 'hex'))}`
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

  getPrivateJwk(): JsonWebKey | undefined {
    const prv = this.keyPair.getPrivate()
    if (!prv) {
      return undefined
    }

    const pubJwk = this.getPublicJwk()
    return {
      ...pubJwk,
      d: prv.toBuffer().toString('base64url'),
    }
  }

  static importDid(did: string) {
    const secp256k1 = new ec('secp256k1')
    const parts = did.split(':')
    if (parts.length < 3) {
      throw new Error('did has invalid format')
    }

    const scheme = parts[0]
    const method = parts[1]
    const version = parts.length > 3 ? parts[2] : '1'
    const multibaseValue = parts.length > 3 ? parts[3] : parts[2]

    if (scheme != 'did') {
      throw new Error('scheme must be "did"')
    }

    if (method != 'key') {
      throw new Error('method must be "key"')
    }

    try {
      Number(version)
    } catch {
      throw new Error('version must be number')
    }

    if (multibaseValue[0] != 'z') {
      throw new Error('multibaseValue must start with z')
    }

    const data = bs58.decode(multibaseValue.substring(1))
    const keyPair = secp256k1.keyFromPublic(data.slice(2))
    return new DidKey(keyPair)
  }
}

export default DidKey
