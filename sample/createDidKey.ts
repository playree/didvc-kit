import DidKey from '@kit/did/didKey'

const main = async () => {
  const key1 = new DidKey()
  console.log('key1:', key1)
  const prv1 = key1.getPrivateJwk()
  console.log('prv1:', prv1)
  const pub1 = key1.getPublicJwk()
  console.log('pub1:', pub1)

  const key2 = DidKey.fromDid(key1.did)
  console.log('key2:', key2)
  const prv2 = key2.getPrivateJwk()
  console.log('prv2:', prv2)
  const pub2 = key2.getPublicJwk()
  console.log('pub2:', pub2)

  const keySecp256k1 = DidKey.fromDid('did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme')
  console.log('use secp256k1:', keySecp256k1)
  const pubSecp256k1 = keySecp256k1.getPublicJwk()
  console.log('secp256k1 PublicKey:', pubSecp256k1)

  const keyP256 = DidKey.fromDid('did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169')
  console.log('use P-256:', keyP256)
  const pubP256 = keyP256.getPublicJwk()
  console.log('P-256 PublicKey:', pubP256)

  const keyEd25519 = DidKey.fromDid('did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp')
  console.log('use Ed25519:', keyEd25519)
  const pubEd25519 = keyEd25519.getPublicJwk()
  console.log('Ed25519 PublicKey:', pubEd25519)
}

main()
