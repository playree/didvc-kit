import { ec, eddsa } from 'elliptic'
import bs58 from 'bs58'

const getDidEc = (keyPair: ec.KeyPair) => {
  const multicodec = 'e701'
  const pubkey = keyPair.getPublic().encode('hex', true)
  return `did:key:z${bs58.encode(Buffer.from(`${multicodec}${pubkey}`, 'hex'))}`
}

const getDidEd = (keyPair: eddsa.KeyPair) => {
  const multicodec = 'ed01'
  const pubkey = keyPair.getPublic('hex')
  return `did:key:z${bs58.encode(Buffer.from(`${multicodec}${pubkey}`, 'hex'))}`
}

const getPublicJwkEc = (keyPair: ec.KeyPair) => {
  const pub = keyPair.getPublic()
  return {
    kty: 'EC',
    crv: 'secp256k1',
    x: pub.getX().toBuffer().toString('base64url'),
    y: pub.getY().toBuffer().toString('base64url'),
  }
}

const getPublicJwkEd = (keyPair: eddsa.KeyPair) => {
  const pub = keyPair.getPublic()
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: pub.toString('base64url'),
  }
}

export class DidKey {
  public did: string
  public keyPair: ec.KeyPair | eddsa.KeyPair

  constructor(keyPair?: ec.KeyPair | eddsa.KeyPair) {
    if (keyPair) {
      this.keyPair = keyPair
    } else {
      const secp256k1 = new ec('secp256k1')
      this.keyPair = secp256k1.genKeyPair()
    }

    if ('ec' in this.keyPair) {
      this.did = getDidEc(this.keyPair)
    } else {
      this.did = getDidEd(this.keyPair)
    }
  }

  getPublicJwk(): JsonWebKey {
    if ('ec' in this.keyPair) {
      return getPublicJwkEc(this.keyPair)
    }
    return getPublicJwkEd(this.keyPair)
  }

  getPrivateJwk(): JsonWebKey | undefined {
    if (!('ec' in this.keyPair)) {
      return undefined
    }

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

  static fromDid(did: string) {
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
    const multicodec = Buffer.from(data.slice(0, 2)).toString('hex')
    switch (multicodec) {
      case 'e701':
        const secp256k1 = new ec('secp256k1')
        return new DidKey(secp256k1.keyFromPublic(data.slice(2)))
      case 'ed01':
        const ed25519 = new eddsa('ed25519')
        return new DidKey(ed25519.keyFromPublic(Buffer.from(data.slice(2))))
      default:
        throw new Error(`multicodec ${multicodec} is not supported`)
    }
  }
}

export default DidKey
