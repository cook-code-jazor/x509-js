import {Base64, UrlSafeBase64} from "./asn1.helper.Base64";
import {
    encode_tag_header,
    encode_contents,
    encode_length,
    asn1_object,
    asn1_sequence,
    asn1_context,
    asn1_set,
    asn1_constructed_context,
    asn1_constructed_sequence,
    asn1_constructed_set,
    asn1_null,
    asn1_raw,
    asn1_bmp_string,
    asn1_bit_string,
    asn1_boolean,
    asn1_general_string,
    asn1_generalized_time,
    asn1_ia5_string,
    asn1_integer,
    asn1_object_identifier,
    asn1_octet_string,
    asn1_printable_string,
    asn1_t61_string,
    asn1_utc_time,
    asn1_utf8_string,
    asn1_visible_string,
    push
} from './asn1.objects'

const ExportFormat = {
    Raw : 0,
    Pem: 1
}
const ecc_curves = {
    P256: 'P-256', //1.2.840.10045.3.1.7
    P384: 'P-384', //1.3.132.0.34
    P521: 'P-521' //1.3.132.0.35
};
export const ecc_curves_oid = {
    'P-256': '1.2.840.10045.3.1.7',
    'P-384': '1.3.132.0.34', //
    'P-521': '1.3.132.0.35' //
};
export const X509Names = {
    O: '2.5.4.10',
    OU: '2.5.4.11',
    C: '2.5.4.6',
    ST: '2.5.4.8',
    L: '2.5.4.7',
    Street: '2.5.4.9',
    E: '1.2.840.113549.1.9.1'
}
export const X509NamesHandler = {
    O: asn1_utf8_string,
    OU: asn1_utf8_string,
    C: asn1_printable_string,
    ST: asn1_utf8_string,
    L: asn1_utf8_string,
    Street: asn1_utf8_string,
    E: asn1_ia5_string
}

export const sha256WithECDsa = '1.2.840.10045.4.3.2'
export const sha256WithRSAEncryption = '1.2.840.113549.1.1.11'

export function generate_rsa_keypair(modulusLength) {
    return crypto.subtle.generateKey({
        name: 'RSASSA-PKCS1-v1_5',
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength,
        hash: 'SHA-256'
    }, true, ["sign", "verify"])
}

export function generate_ecc_keypair(namedCurve) {
    return crypto.subtle.generateKey({
            name: 'ECDSA',
            namedCurve
        }, true, ["sign", "verify"]
    )
}

function generate_ecc_private_key(jwt) {
    const bytes = []
    asn1_constructed_sequence(
        asn1_integer(1),
        asn1_octet_string(UrlSafeBase64.decode(jwt.d)),
        asn1_constructed_context(0,
            asn1_object_identifier(ecc_curves_oid[jwt.crv]),
        ),
        asn1_constructed_context(1,
            asn1_bit_string([0x04, ...UrlSafeBase64.decode(jwt.x), ...UrlSafeBase64.decode(jwt.y)]),
        ),
    ).encode(bytes)
    return bytes;
}

function generate_rsa_private_key(jwt) {
    const isECC = jwt.kty === 'EC'
    const bytes = []
    asn1_constructed_sequence(
        asn1_integer(0),
        asn1_integer(UrlSafeBase64.decode(jwt.n)),
        asn1_integer(UrlSafeBase64.decode(jwt.e)),
        asn1_integer(UrlSafeBase64.decode(jwt.d)),
        asn1_integer(UrlSafeBase64.decode(jwt.p)),
        asn1_integer(UrlSafeBase64.decode(jwt.q)),
        asn1_integer(UrlSafeBase64.decode(jwt.dp)),
        asn1_integer(UrlSafeBase64.decode(jwt.dq)),
        asn1_integer(UrlSafeBase64.decode(jwt.qi)),
    ).encode(bytes)
    return bytes;
}

function generate_pkcs8_key(jwt) {
    const isECC = jwt.kty === 'EC'
    const bytes = []
    asn1_constructed_sequence(
        asn1_integer(0),
        asn1_constructed_sequence(
            asn1_object_identifier(isECC ? '1.2.840.10045.2.1' : '1.2.840.113549.1.1.1'),
            isECC ? asn1_object_identifier(ecc_curves_oid[jwt.crv]) : asn1_null(),
        ),
        asn1_octet_string(isECC ? generate_ecc_private_key(jwt) : generate_rsa_private_key(jwt))
    ).encode(bytes)
    return bytes;
}

function generate_ecc_public_key(jwt) {
    return [0x04, ...UrlSafeBase64.decode(jwt.x), ...UrlSafeBase64.decode(jwt.y)];
}

function generate_rsa_public_key(jwt) {
    const bytes = []
    asn1_constructed_sequence(
        asn1_integer(UrlSafeBase64.decode(jwt.n)),
        asn1_integer(UrlSafeBase64.decode(jwt.e)),
    ).encode(bytes)
    return bytes;
}

function generate_public_key(jwt) {
    const isECC = jwt.kty === 'EC'
    const bytes = []
    asn1_constructed_sequence(
        asn1_constructed_sequence(
            asn1_object_identifier(isECC ? '1.2.840.10045.2.1' : '1.2.840.113549.1.1.1'),
            isECC ? asn1_object_identifier(ecc_curves_oid[jwt.crv]) : asn1_null(),
        ),
        asn1_bit_string(isECC ? generate_ecc_public_key(jwt) : generate_rsa_public_key(jwt))
    ).encode(bytes)
    return bytes;
}

export function export_pkcs8_private_key(privateKey, format) {
    if (ExportFormat.Pem !== format) format = ExportFormat.Raw;
    return crypto.subtle.exportKey('jwk', privateKey).then(info => {
        const privateKeyBytes = generate_pkcs8_key(info)

        return format === ExportFormat.Pem ? build_pem('PRIVATE KEY', privateKeyBytes) : privateKeyBytes
    })
}

export function export_public_key(publicKey, format) {
    if (ExportFormat.Pem !== format) format = ExportFormat.Raw;
    return crypto.subtle.exportKey('jwk', publicKey).then(info => {
        const publicKeyBytes = generate_public_key(info)

        return format === ExportFormat.Pem ? build_pem('PUBLIC KEY', publicKeyBytes) : publicKeyBytes

    })
}
export function export_keys(privateKey) {
    return crypto.subtle.exportKey('jwk', privateKey).then(info => {
        return {
            private_key: generate_pkcs8_key(info),
            public_key: generate_public_key(info)
        }
    })
}


export function sign(key, body, algorithmType) {
    const algorithm = algorithmType === 'RSA' ? {
        name: 'RSASSA-PKCS1-v1_5'
    } : {
        name: 'ECDSA',
        hash: 'SHA-256'
    }
    return crypto.subtle.sign(algorithm, key, new Uint8Array(body)).then(res => {
        const bytes = new Uint8Array(res)
        if (algorithmType === 'RSA') return bytes;

        const result = []

        asn1_constructed_sequence(
            asn1_integer(bytes.slice(0, bytes.length / 2)),
            asn1_integer(bytes.slice(bytes.length / 2))
        ).encode(result);
        return result;
    })
}
export function build_pem( type, bytes) {
    return '-----BEGIN ' + type + '-----\r\n'
        + Base64.encode(bytes, null, 64)
        + '\r\n-----END ' + type + '-----\r\n';
}

export function gen_keypair(algorithmType, algorithmParam){

    return algorithmType === 'ECC' ?
         generate_ecc_keypair(algorithmParam || 'P-384') :
         generate_rsa_keypair(algorithmParam || 2048);
}

export function check_params(algorithmType, algorithmParam){

    if (algorithmType !== 'ECC' && algorithmType !== 'RSA') throw new Error('only support: ECC/RSA')
    if (algorithmType === 'ECC' && algorithmParam !== 'P-256' && algorithmParam !== 'P-384' && algorithmParam !== 'P-521' && algorithmParam !== undefined)
        throw new Error('only support: P-256/P-384/P-521, default: P-384')
    if (algorithmType === 'RSA' && algorithmParam !== 2048 && algorithmParam !== 4096 && algorithmParam !== undefined)
        throw new Error('only support: 2048/4096, default: 2048')
}
export async function generate_asymmetric_keypair(algorithmType, algorithmParam) {

    check_params( algorithmType, algorithmParam)

    const keypair = await gen_keypair(algorithmType, algorithmParam)

    const keys = await export_keys(keypair.privateKey)
    return {
        private_key: build_pem('PRIVATE KEY', keys.private_key),
        public_key: build_pem('PUBLIC KEY', keys.public_key)
    };
}
