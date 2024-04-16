import {
    asn1_context,
    asn1_constructed_context,
    asn1_constructed_sequence,
    asn1_constructed_set,
    asn1_null,
    asn1_raw,
    asn1_bit_string,
    asn1_integer,
    asn1_object_identifier,
    asn1_octet_string,
    asn1_utf8_string
} from './asn1.objects'
import UTF8String from "./asn1.helper.UTF8String";
import {
    build_pem, check_params,
    export_keys, gen_keypair,
    sha256WithECDsa,
    sha256WithRSAEncryption, sign,
    X509Names,
    X509NamesHandler
} from "./x509";

function build_x509name(key, x509Names) {
    if (!x509Names[key]) return null;
    return asn1_constructed_set(
        asn1_constructed_sequence(
            asn1_object_identifier(X509Names[key]),
            X509NamesHandler[key](x509Names[key])
        )
    )
}
export default function csr(commonName) {
    const commonName_ = commonName;
    const san = [];
    const x509Names = {}

    function set_get(name, value) {
        if (value === undefined) return x509Names[name]
        x509Names[name] = value
        return instance;
    }

    const instance = {
        add_san: (name) => instance.san(name),
        san(name) {
            if(!(name instanceof Array)) name = [name]
            name.forEach(name => {
                if(name && san.indexOf(name) === -1) san.push(name)
            })
            return instance;
        },
        clear_san() {
            san.length = 0;
            return instance;
        },
        org: (value) => set_get('O', value),
        org_unit: (value) => set_get('OU', value),
        country: (value) => set_get('C', value),
        state: (value) => set_get('ST', value),
        location: (value) => set_get('L', value),
        street: (value) => set_get('Street', value),
        email: (value) => set_get('E', value),
        generate: (algorithmType, algorithmParam) => generate_csr(commonName_, san, algorithmType, algorithmParam, x509Names)
    }
    return instance
}


function build_san(names) {
    const bytes = [];
    asn1_constructed_sequence(function (children) {
        names.forEach(t => {
            children.push(asn1_context(2, UTF8String(t).getBytesArray()))
        })
    }).encode(bytes)
    return bytes
}

function build_root(commonName, x509Names, subjectAltNames, publicKey){
    const root = asn1_constructed_sequence(
        asn1_integer(0),
        asn1_constructed_sequence(
            asn1_constructed_set(
                asn1_constructed_sequence(
                    asn1_object_identifier('2.5.4.3'),
                    asn1_utf8_string(commonName)
                )
            ),
            build_x509name('O', x509Names),
            build_x509name('OU', x509Names),
            build_x509name('C', x509Names),
            build_x509name('ST', x509Names),
            build_x509name('L', x509Names),
            build_x509name('Street', x509Names),
            build_x509name('E', x509Names)
        ),
        asn1_raw(publicKey),
        subjectAltNames.length === 0 ? null : asn1_constructed_context(0,
            asn1_constructed_sequence(
                asn1_object_identifier('1.2.840.113549.1.9.14'),
                asn1_constructed_set(
                    asn1_constructed_sequence(
                        asn1_constructed_sequence(
                            asn1_object_identifier('2.5.29.17'),
                            asn1_octet_string(build_san(subjectAltNames))
                        )
                    )
                )
            )
        )
    )
    const bytes = [];
    root.encode(bytes)
    return bytes;
}
function build_csr(algorithmType, body, signature){
    const csr = [];

    asn1_constructed_sequence(
        asn1_raw(body),
        asn1_constructed_sequence(
            asn1_object_identifier(algorithmType === 'ECC' ? sha256WithECDsa : sha256WithRSAEncryption),
            algorithmType === 'ECC' ? asn1_raw([]) : asn1_null()
        ),
        asn1_bit_string(signature)
    ).encode(csr);
    return csr;
}
async function generate_csr(commonName, subjectAltNames, algorithmType, algorithmParam, x509Names) {
    check_params( algorithmType, algorithmParam)
    if (!subjectAltNames) subjectAltNames = []


    x509Names = x509Names || {}

    const keypair = await gen_keypair(algorithmType, algorithmParam)

    const keys = await export_keys(keypair.privateKey)

    const bytes = build_root(commonName, x509Names, subjectAltNames, keys.public_key)

    const signature = await sign(keypair.privateKey, bytes, algorithmType)


    const csr = build_csr(algorithmType, bytes, signature);

    return {
        private_key: build_pem('PRIVATE KEY', keys.private_key),
        public_key: build_pem('PUBLIC KEY', keys.public_key),
        csr: build_pem('CERTIFICATE REQUEST', csr)
    };
}
