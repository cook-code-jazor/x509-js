
import {generate_rsa_keypair, generate_ecc_keypair, csr, export_pkcs8_private_key, export_public_key} from "./x509";

window.X509 = {
    generate_rsa_keypair, generate_ecc_keypair, csr, export_pkcs8_private_key, export_public_key
}
