import { ec, eddsa } from 'elliptic'
import bs58 from 'bs58'
import { getNameFromData, addPrefix, CodecName, rmPrefix } from 'multicodec'

type EllipticEc = 'secp256k1' | 'p256'
type EllipticEd = 'ed25519'
type SupportedCrv = 'secp256k1' | 'P-256' | 'Ed25519'

/**
 * Verification Methods
 */
const VM = {
  secp256k1: {
    kty: 'EC',
    crv: 'secp256k1',
    type: 'EcdsaSecp256k1VerificationKey2019',
    elliptic: 'secp256k1' as EllipticEc,
  },
  p256: {
    kty: 'EC',
    crv: 'P-256',
    type: 'JsonWebKey2020',
    elliptic: 'p256' as EllipticEc,
  },
  ed25519: {
    kty: 'OKP',
    crv: 'Ed25519',
    type: 'Ed25519VerificationKey2018',
    elliptic: 'ed25519' as EllipticEd,
  },
}

const getDidEc = (keyPair: ec.KeyPair, codecName: CodecName) => {
  const pubkey = keyPair.getPublic().encodeCompressed('hex')
  return `did:key:z${bs58.encode(addPrefix(codecName, Buffer.from(pubkey, 'hex')))}`
}

const getDidEd = (keyPair: eddsa.KeyPair, codecName: CodecName) => {
  const pubkey = keyPair.getPublic()
  return `did:key:z${bs58.encode(addPrefix(codecName, pubkey))}`
}

const getPublicJwkEc = (keyPair: ec.KeyPair, op: { kty: string; crv: string }) => {
  const pub = keyPair.getPublic()
  return {
    kty: op.kty,
    crv: op.crv,
    x: pub.getX().toBuffer().toString('base64url'),
    y: pub.getY().toBuffer().toString('base64url'),
  }
}

const getPublicJwkEd = (keyPair: eddsa.KeyPair, op: { kty: string; crv: string }) => {
  const pub = keyPair.getPublic()
  return {
    kty: op.kty,
    crv: op.crv,
    x: pub.toString('base64url'),
  }
}

export class DidKey {
  public did: string
  public keyPair: ec.KeyPair | eddsa.KeyPair
  public crv: SupportedCrv

  constructor(key?: { keyPair: ec.KeyPair | eddsa.KeyPair; crv: SupportedCrv }) {
    if (key) {
      this.keyPair = key.keyPair
      this.crv = key.crv
    } else {
      const secp256k1 = new ec(VM.secp256k1.elliptic)
      this.keyPair = secp256k1.genKeyPair()
      this.crv = 'secp256k1'
    }

    if ('ec' in this.keyPair) {
      switch (this.crv) {
        case 'secp256k1':
          this.did = getDidEc(this.keyPair, 'secp256k1-pub')
          break
        case 'P-256':
          this.did = getDidEc(this.keyPair, 'p256-pub')
          break
        default:
          throw new Error('not supported')
      }
    } else {
      switch (this.crv) {
        case 'Ed25519':
          this.did = getDidEd(this.keyPair, 'ed25519-pub')
          break
        default:
          throw new Error('not supported')
      }
    }
  }

  getPublicJwk(): JsonWebKey {
    switch (this.crv) {
      case 'secp256k1':
        return getPublicJwkEc(this.keyPair as ec.KeyPair, VM.secp256k1)
      case 'P-256':
        return getPublicJwkEc(this.keyPair as ec.KeyPair, VM.p256)
      case 'Ed25519':
        return getPublicJwkEd(this.keyPair as eddsa.KeyPair, VM.ed25519)
    }
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
    const multicodec = getNameFromData(data)
    switch (multicodec) {
      case 'secp256k1-pub':
        const secp256k1 = new ec(VM.secp256k1.elliptic)
        return new DidKey({ keyPair: secp256k1.keyFromPublic(rmPrefix(data)), crv: 'secp256k1' })
      case 'p256-pub':
        const p256 = new ec(VM.p256.elliptic)
        return new DidKey({ keyPair: p256.keyFromPublic(rmPrefix(data)), crv: 'P-256' })
      case 'ed25519-pub':
        const ed25519 = new eddsa(VM.ed25519.elliptic)
        return new DidKey({ keyPair: ed25519.keyFromPublic(Buffer.from(rmPrefix(data))), crv: 'Ed25519' })
      default:
        throw new Error(`multicodec ${multicodec} is not supported`)
    }
  }
}

export default DidKey
