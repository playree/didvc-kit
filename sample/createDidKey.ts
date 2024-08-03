import DidKey from '@kit/did/didKey'

const main = async () => {
  const key1 = new DidKey()
  console.log('key1:', key1)

  const prv1 = key1.getPrivateJwk()
  console.log('prv1:', prv1)

  const pub1 = key1.getPublicJwk()
  console.log('pub1:', pub1)

  const key2 = DidKey.importDid(key1.did)
  console.log('key2:', key2)

  const prv2 = key2.getPrivateJwk()
  console.log('prv2:', prv2)

  const pub2 = key2.getPublicJwk()
  console.log('pub2:', pub2)

  const key3 = DidKey.importDid('did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp')
  console.log('key3:', key3)

  const pub3 = key3.getPublicJwk()
  console.log('pub3:', pub3)
}

main()
