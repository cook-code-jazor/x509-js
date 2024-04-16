```javascript
const csr = X509.csr('name.com');
const response = await csr.generate('ECC')

console.log(response)
```

```javascript
const csr = X509.csr('name.com')
  .san('name.com')
  .san('*.name.com')
  .san(['*.loc.name.com', '*.sev.name.com'])
  .org('orgname')
  .org_unit('Unit')
  .email('test@gm.com')
  .state('State')
  .country('CN')
  .location('City');
const response = await csr.generate('ECC')

console.log(response)
```
```javascript

const response = await X509.generate_asymmetric_keypair('ECC')

console.log(response)
```
