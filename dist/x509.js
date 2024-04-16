(()=>{"use strict";const t=["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","0","1","2","3","4","5","6","7","8","9","+","/","="],e=[],n=["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","0","1","2","3","4","5","6","7","8","9","-","_","="],r=[];for(let o=0;o<t.length;o++)e[t[o].charCodeAt(0)]=o,r[n[o].charCodeAt(0)]=o;const o=function(e,n,r){n=n||t;for(var o,c,i,u,s="",f="",a="",d=0,l=e.length,p=l-l%3,h=0;d<p;)i=(3&(o=e[d++]))<<4|(c=e[d++])>>4,u=(15&c)<<2|(f=e[d++])>>6,a=63&f,s+=n[o>>2]+n[i]+n[u]+n[a],r>0&&(h+=4)%r==0&&(s+="\r\n");return l-p==2?(o=e[d++],c=e[d++],s+=n[o>>2]+n[(3&o)<<4|c>>4]+n[(15&c)<<2]+"="):l-p==1&&(s+=n[(o=e[d++])>>2]+n[(3&o)<<4]+"=="),"\n"===s.charAt(s.length-1)&&(s=s.substr(0,s.length-2)),s},c=function(t,n){if(n=n||e,""===(t=t.replace(/\s/g,"")))return[];var r,o,c,i,u,s=[],f="",a=0,d=t.length,l=d;for("="===t.slice(-1)&&(l=d-4);a<l;)r=(c=n[t.charCodeAt(a++)])<<2|(i=n[t.charCodeAt(a++)])>>4,o=(15&i)<<4|(u=n[t.charCodeAt(a++)])>>2,f=(3&u)<<6|n[t.charCodeAt(a++)],s.push(r,o,f);return d!==l&&(c=n[t.charCodeAt(a++)],i=n[t.charCodeAt(a++)],"=="===t.slice(-2)?s.push(c<<2|i>>4):"="===t.slice(-1)&&(u=n[t.charCodeAt(a++)],s.push(c<<2|i>>4,(15&i)<<4|u>>2))),s},i={encode:o,decode:c},u={encode:function(t,e){return o(t,n,e).replace(/=+$/,"")},decode:function(t){for(;t.length%4!=0;)t+="=";return c(t,r)}},s={Boolean:1,Integer:2,BitString:3,OctetString:4,Null:5,ObjectIdentifier:6,Enumerated:10,Sequence:16,Set:17,UTF8String:12,NumericString:18,PrintableString:19,T61String:20,IA5String:22,UTCTime:23,GeneralizedTime:24,VisibleString:26,GeneralString:27,BMPString:30,TagNumberMask:31,ConstructedFlag:32,ConstructedSequence:48,ConstructedSet:49,ContextSpecificTagFlag:128,ContextSpecificConstructedTag0:160,ContextSpecificConstructedTag1:161,ContextSpecificConstructedTag2:162,ContextSpecificConstructedTag3:163,TagClassMask:192,VALUE_NAME_MAP:{16:"SEQUENCE",17:"SET",48:"SEQUENCE",49:"SET",6:"OBJECT IDENTIFIER",2:"INTEGER",1:"BOOLEAN",3:"BIT STRING",4:"OCTET STRING",5:"NULL"}};for(const t in s)s.hasOwnProperty(t)&&"VALUE_NAME_MAP"!==t&&!s.VALUE_NAME_MAP.hasOwnProperty(s[t])&&(s.VALUE_NAME_MAP[s[t]]=t);const f=s,a={decode:function(t,e,n){e=void 0===e?0:e,n=void 0===n?t.length:n;let r="";const o=t[e];r+=Math.floor(o/40)+"."+o%40;let c,i,u=!0,s=0;for(let o=1;o<n;o++)c=t[e+o],i=127&c,u&&(r+=".",u=!1),s<<=7,s+=i,c===i&&(r+=s,s=0,u=!0);return r},encode:function(t){const e=t.split(".").map((t=>parseInt(t))),n=[];n.push(40*e[0]+e[1]);for(let t=2;t<e.length;t++){let r=e[t];if(r<=127){n.push(r);continue}const o=[];let c=!1;for(;r>0;){let t=127&r;c&&(t|=128),o.unshift(t),r>>=7,c||(c=!0)}Array.prototype.push.apply(n,o)}return n}};function d(t,e,n){let r=null;if("string"==typeof t){if(void 0!==e)throw new Error("expect 'undefined' for argument offset");r=t,e=0,n=(t=function(t){const e=[];for(let n=0;n<t.length;n++){const r=t.charCodeAt(n);r<=127?e.push(r):r<=2047?e.push(r>>6|192,63&r|128):r<=65535?e.push(r>>12|224,r>>6&63|128,63&r|128):e.push(r>>18|240,r>>12&63|128,r>>6&63|128,63&r|128)}return e}(r)).length}if(e+n>t.length)throw new Error("offset out of range");void 0===e&&(e=0),void 0===n&&(n=t.length);const o=e,c=n;let i=e;const u=e+n;function s(){const e=t[i];return e<128?1:e<224?2:e<240?3:4}function f(){const e=t[i++];if(e<128)return e;const n=t[i++];if(e<224)return(31&e)<<6|63&n;const r=t[i++];if(e<240)return(15&e)<<12|(63&n)<<6|63&r;return(7&e)<<18|(63&n)<<12|(63&r)<<6|63&t[i++]}return{toString:function(){if(null!==r)return r;const t=[];for(;i<u;){const e=s();if(i+e>u)throw new Error("unformed utf8 bytes array");t.push(f())}return r=String.fromCharCode.apply(null,t)},getBytesArray:()=>t.slice(o,o+c)}}const l=function(t,e){if(e instanceof Uint8Array){const t=[];e.forEach((e=>{t.push(e)})),e=t}Array.prototype.push.apply(t,e)};function p(t,e){return e=e||[],{encode(n){"function"==typeof e&&(e=e()),"string"==typeof e&&(e=e.split("").map((t=>t.charCodeAt(0)))),g(t,e.length,n),l(n,e)}}}function h(t,...e){if(1===e.length&&"function"==typeof e[0]){const t=[];e[0](t),e=t}return{encode(n){const r=[];e.forEach((t=>t&&t.encode(r))),function(t,e,n){g(t,e.length,n),l(n,e)}(t,r,n)}}}function g(t,e,n){n.push(t),function(t,e){if(t<128)return void e.push(t);const n=[];let r=0;for(;t>0;)n.unshift(255&t),t>>=8,r++;n.unshift(128|r),l(e,n)}(e,n)}function y(t,...e){return h(f.ContextSpecificTagFlag|f.ConstructedFlag|t,...e)}function C(...t){return h(f.Sequence|f.ConstructedFlag,...t)}function S(...t){return h(f.Set|f.ConstructedFlag,...t)}function E(){return p(f.Null)}function A(t){return{encode(e){l(e,t)}}}function T(t){return{encode(e){g(f.BitString,t.length+1,e),e.push(0),l(e,t)}}}function v(t,e){let n=[];if(t instanceof Uint8Array){const e=[];t.forEach((t=>{e.push(t)})),t=e}if(t instanceof Array){for(n=t,!0===e&&n.reverse();0===n[0];)n.shift();(128&n[0])>0&&n.unshift(0)}else if("number"==typeof t){for(;t>255;)n.unshift(255&t),t>>=8;n.unshift(t),(128&t)>0&&n.unshift(0)}return p(f.Integer,n)}function P(t){return"string"==typeof t&&(t=a.encode(t)),p(f.ObjectIdentifier,t)}function w(t){return p(f.OctetString,t)}function _(t){return p(f.UTF8String,d(t).getBytesArray())}const U={"P-256":"1.2.840.10045.3.1.7","P-384":"1.3.132.0.34","P-521":"1.3.132.0.35"},I={O:"2.5.4.10",OU:"2.5.4.11",C:"2.5.4.6",ST:"2.5.4.8",L:"2.5.4.7",Street:"2.5.4.9",E:"1.2.840.113549.1.9.1"},b={O:_,OU:_,C:function(t){return p(f.PrintableString,t)},ST:_,L:_,Street:_,E:function(t){return p(f.IA5String,t)}},m="1.2.840.10045.4.3.2",k="1.2.840.113549.1.1.11";function N(t){const e="EC"===t.kty,n=[];return C(v(0),C(P(e?"1.2.840.10045.2.1":"1.2.840.113549.1.1.1"),e?P(U[t.crv]):E()),w(e?function(t){const e=[];return C(v(1),w(u.decode(t.d)),y(0,P(U[t.crv])),y(1,T([4,...u.decode(t.x),...u.decode(t.y)]))).encode(e),e}(t):function(t){t.kty;const e=[];return C(v(0),v(u.decode(t.n)),v(u.decode(t.e)),v(u.decode(t.d)),v(u.decode(t.p)),v(u.decode(t.q)),v(u.decode(t.dp)),v(u.decode(t.dq)),v(u.decode(t.qi))).encode(e),e}(t))).encode(n),n}function O(t){const e="EC"===t.kty,n=[];return C(C(P(e?"1.2.840.10045.2.1":"1.2.840.113549.1.1.1"),e?P(U[t.crv]):E()),T(e?function(t){return[4,...u.decode(t.x),...u.decode(t.y)]}(t):function(t){const e=[];return C(v(u.decode(t.n)),v(u.decode(t.e))).encode(e),e}(t))).encode(n),n}function R(t){return crypto.subtle.exportKey("jwk",t).then((t=>({private_key:N(t),public_key:O(t)})))}function L(t,e){return"-----BEGIN "+t+"-----\r\n"+i.encode(e,null,64)+"\r\n-----END "+t+"-----\r\n"}function B(t,e){return e[t]?S(C(P(I[t]),b[t](e[t]))):null}function x(t,e){return"ECC"===t?(r=e||"P-384",crypto.subtle.generateKey({name:"ECDSA",namedCurve:r},!0,["sign","verify"])):(n=e||2048,crypto.subtle.generateKey({name:"RSASSA-PKCS1-v1_5",publicExponent:new Uint8Array([1,0,1]),modulusLength:n,hash:"SHA-256"},!0,["sign","verify"]));var n,r}function K(t,e){if("ECC"!==t&&"RSA"!==t)throw new Error("only support: ECC/RSA");if("ECC"===t&&"P-256"!==e&&"P-384"!==e&&"P-521"!==e&&void 0!==e)throw new Error("only support: P-256/P-384/P-521, default: P-384");if("RSA"===t&&2048!==e&&4096!==e&&void 0!==e)throw new Error("only support: 2048/4096, default: 2048")}window.X509={csr:function(t){const e=t,n=[],r={};function o(t,e){if(void 0===e)return r[t];r[t]=e}return{add_san(t){n.push(t)},clear_san(){n.length=0},org:t=>o("O",t),org_unit:t=>o("OU",t),country:t=>o("C",t),state:t=>o("ST",t),location:t=>o("L",t),street:t=>o("Street",t),email:t=>o("E",t),generate:(t,o)=>async function(t,e,n,r,o){K(n,r),e&&0!==e.length||(e=[t]);o=o||{};const c=await x(n,r),i=await R(c.privateKey),u=function(t,e,n,r){const o=C(v(0),C(S(C(P("2.5.4.3"),_(t))),B("O",e),B("OU",e),B("C",e),B("ST",e),B("L",e),B("Street",e),B("E",e)),A(r),y(0,C(P("1.2.840.113549.1.9.14"),S(C(C(P("2.5.29.17"),w(function(t){const e=[];return C((function(e){t.forEach((t=>{var n,r;e.push((n=2,r=d(t).getBytesArray(),p(n|f.ContextSpecificTagFlag,r)))}))})).encode(e),e}(n)))))))),c=[];return o.encode(c),c}(t,o,e,i.public_key),s=await function(t,e,n){const r="RSA"===n?{name:"RSASSA-PKCS1-v1_5"}:{name:"ECDSA",hash:"SHA-256"};return crypto.subtle.sign(r,t,new Uint8Array(e)).then((t=>{const e=new Uint8Array(t);if("RSA"===n)return e;const r=[];return C(v(e.slice(0,e.length/2)),v(e.slice(e.length/2))).encode(r),r}))}(c.privateKey,u,n),a=function(t,e,n){const r=[];return C(A(e),C(P("ECC"===t?m:k),"ECC"===t?A([]):E()),T(n)).encode(r),r}(n,u,s);return{private_key:L("PRIVATE KEY",i.private_key),public_key:L("PUBLIC KEY",i.public_key),csr:L("CERTIFICATE REQUEST",a)}}(e,n,t,o,r)}},generate_asymmetric_keypair:async function(t,e){K(t,e);const n=await x(t,e),r=await R(n.privateKey);return{private_key:L("PRIVATE KEY",r.private_key),public_key:L("PUBLIC KEY",r.public_key)}}}})();