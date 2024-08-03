import DidKey from '@kit/did/didKey'

const main = async () => {
  const key = new DidKey()
  console.log('key:', key)

  const jwk = key.getPrivateJwk()
  console.log('jwk:', jwk)
}

main()
