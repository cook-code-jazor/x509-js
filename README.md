```
X509.csr(commonName:string) : CSRInfo
```
```
CSRInfo {
  san(san:string) : CSRInfo,
  san([san1, san2, san3]) : CSRInfo,
  org(org:string) : CSRInfo,
  org_unit(unit:string) : CSRInfo,
  country(countryCode:string) : CSRInfo,
  state(stateName:string) : CSRInfo,
  location(locationName:string) : CSRInfo,
  street(streetName:string) : CSRInfo,
  email(emailAddress:string) : CSRInfo,
  generate(alg:string[, alg_param:string|int]) : Promise<CSRResult>
}

CSRInfo.generate('ECC', 'P-256' | 'P-384' | 'P-521')
CSRInfo.generate('RSA', 2048 | 4096)
```
```
CSRResult {
  csr:string,
  private_key:string,
  public_key:string
}
```
```javascript
//CSR with CommonName only
const csr = X509.csr('name.com');
const response = await csr.generate('ECC')

console.log(response)
```

```javascript
//CSR with CommonName, SAN and other fields
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
//generate keypair
const response = await X509.generate_asymmetric_keypair('ECC')

console.log(response)
```
