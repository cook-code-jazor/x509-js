```
X509.csr(string commonName) : CSRInfo
```
```
CSRInfo {
  san(string san) : CSRInfo,
  san([san1, san2, san3]) : CSRInfo,
  org(string org) : CSRInfo,
  org_unit(string unit) : CSRInfo,
  country(string countryCode) : CSRInfo,
  state(string stateName) : CSRInfo,
  location(string locationName) : CSRInfo,
  street(string streetName) : CSRInfo,
  email(string emailAddress) : CSRInfo,
  generate(string alg[, string|int alg_param]) : Promise<CSRResult>
}

CSRInfo.generate('ECC', 'P-256' | 'P-384' | 'P-521')
CSRInfo.generate('RSA', 2048 | 4096)
```
```
CSRResult {
  csr,
  private_key,
  public_key
}
```
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
