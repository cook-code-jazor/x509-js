```js
    const csr = X509.csr('name.com')
    csr.add_san('name.com')
    csr.add_san('*.name.com')
    csr.org('ORGNAME')
    csr.org_unit('Unit')
    csr.email('test@gm.com')
    csr.state('State')
    csr.country('CN')
    csr.location('City')
    const response = await csr.generate('ECC')
    
    console.log(response)
```
