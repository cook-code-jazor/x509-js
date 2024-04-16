import DerTag from "./asn1.tags";
import ObjectIdentifier from "./asn1.oid";
import UTF8String from "./asn1.helper.UTF8String";

const empty_array = [];
export const push = function (target, source){
    if(source instanceof Uint8Array){
        const value_ = []
        source.forEach(v => {
            value_.push(v)
        })
        source = value_
    }
    Array.prototype.push.apply(target, source);
}
export function asn1_object(tag, ...contents){
    return {
        encode(bytes){
            let length = contents.reduce((p, c) => p + c.length, 0)
            encode_tag_header(tag, length, bytes);

            contents.forEach(t => {
                if(typeof t === 'string') t = t.split('').map(t => t.charCodeAt(0))
                push(bytes, t)
            })
        }
    }
}
export function asn1_sequence(tag, ...children){
    if(children.length === 1 && typeof children[0] === 'function'){
        const children_ = [];
        children[0](children_);
        children = children_;
    }
    return {
        encode(bytes){
            const sub_bytes = []
            children.forEach(t => t && t.encode(sub_bytes))

            encode_contents(tag, sub_bytes, bytes)
        }
    }
}
export function encode_length(length, bytes){
    if(length < 0x80){
        bytes.push(length);
        return;
    }
    const sub_bytes = [];
    let idx = 0;
    while (length > 0){
        sub_bytes.unshift(length & 0xff)
        length >>= 8;
        idx++;
    }
    sub_bytes.unshift(0x80 | idx)

    push(bytes, sub_bytes)
}
export function encode_tag_header(tag, length, bytes){
    bytes.push(tag)
    encode_length(length, bytes);
}
export function encode_contents(tag, contents, bytes){
    encode_tag_header(tag, contents.length, bytes);
    push(bytes, contents)
}
export function asn1_context(flag, contents){
    return asn1_object(flag | DerTag.ContextSpecificTagFlag, contents)
}
export function asn1_set(...children){
    return asn1_sequence( DerTag.ConstructedSet, ...children)
}
export function asn1_constructed_context(flag, ...children){
    return asn1_sequence( DerTag.ContextSpecificTagFlag | DerTag.ConstructedFlag | flag , ...children)
}
export function asn1_constructed_sequence(...children){
    return asn1_sequence( DerTag.Sequence | DerTag.ConstructedFlag , ...children)
}
export function asn1_constructed_set(...children){
    return asn1_sequence( DerTag.Set | DerTag.ConstructedFlag , ...children)
}
export function asn1_null(){
    return asn1_object( DerTag.Null)
}
export function asn1_raw(contents){
    return {
        encode(bytes){
            push(bytes, contents)
        }
    }
}
export function asn1_bmp_string(contents){
    return asn1_object( DerTag.BMPString, contents)
}
export function asn1_bit_string(contents){
    return {
        encode(bytes){
            encode_tag_header(DerTag.BitString, contents.length + 1, bytes);
            bytes.push(0)
            push(bytes, contents)
        }
    }
}
export function asn1_boolean(value){
    return asn1_object( DerTag.Boolean, [value ? 255 : 0])
}
export function asn1_general_string(contents){
    return asn1_object( DerTag.GeneralString, contents)
}
export function asn1_generalized_time(contents){
    return asn1_object( DerTag.GeneralizedTime, contents)
}
export function asn1_utc_time(contents){
    return asn1_object( DerTag.UTCTime, contents)
}
export function asn1_ia5_string(contents){
    return asn1_object( DerTag.IA5String, contents)
}
export function asn1_numeric_string(contents){
    return asn1_object( DerTag.NumericString, contents)
}
export function asn1_integer(value, isLittle){
    let contents = [];
    if(value instanceof Uint8Array){
        const value_ = []
        value.forEach(v => {
            value_.push(v)
        })
        value = value_
    }
    if(value instanceof Array){
        contents = value
        if(isLittle === true) contents.reverse()

        while (contents[0] === 0) contents.shift()
        if((contents[0] & 0x80) > 0) {
            contents.unshift(0)
        }
    }else if(typeof value === 'number'){
        while (value > 0xff){
            contents.unshift(value & 0xff)
            value >>= 8;
        }
        contents.unshift(value)
        if((value & 0x80) > 0) contents.unshift(0)
    }

    return asn1_object( DerTag.Integer, contents)
}
export function asn1_object_identifier(oid){
    if(typeof  oid === 'string') oid = ObjectIdentifier.encode(oid)
    return asn1_object( DerTag.ObjectIdentifier, oid)
}
export function asn1_octet_string(contents){
    return asn1_object( DerTag.OctetString, contents)
}
export function asn1_printable_string(contents){
    return asn1_object( DerTag.PrintableString, contents)
}
export function asn1_t61_string(contents){
    return asn1_object( DerTag.T61String, contents)
}
export function asn1_utf8_string(contents){
    return asn1_object( DerTag.UTF8String, UTF8String(contents).getBytesArray())
}
export function asn1_visible_string(contents){
    return asn1_object( DerTag.VisibleString, contents)
}
