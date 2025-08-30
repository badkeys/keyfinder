/*
 ECDSA keys (P256/P384) from RFC 9500
 spkisha256:b2b04340cfaee616ec9c2c62d261b208e54bb197498df52e8cadede23ac0ba5e
 spkisha256:c4c10105a0be0ed4dd3354428dc38a9bfee64da141ce16e75c94eda272f9dd3a
*/

p256key = ("-----BEGIN EC PRIVATE KEY-----\n" +
           "MHcCAQEEIObLW92AqkWunJXowVR2Z5/+yVPBaFHnEedDk5WJxk/BoAoGCCqGSM49\n" +
           "AwEHoUQDQgAEQiVI+I+3gv+17KN0RFLHKh5Vj71vc75eSOkyMsxFxbFsTNEMTLjV\n" +
           "uKFxOelIgsiZJXKZNCX0FBmrfpCkKklCcg==\n" +
           "-----END EC PRIVATE KEY-----\n");
console.log(p256key);

p384key = ('-----BEGIN EC PRIVATE KEY-----\n' +
           'MIGkAgEBBDDiVjMo36v2gYhga5EyQoHB1YpEVkMbCdUQs1/syfMHyhgihG+iZxNx\n' +
           'qagbrA41dJ2gBwYFK4EEACKhZANiAARbCQG4hSMpbrkZ1Q/6GpyzdLxNQJWGKCv+\n' +
           'yhGx2VrbtUc0r1cL+CtyKM8ia89MJd28/jsaOtOUMO/3Y+HWjS4VHZFyC3eVtY2m\n' +
           's0Y5YTqPubWo2kjGdHEX+ZGehCTzfsg=\n' +
           '-----END EC PRIVATE KEY-----\n');
console.log(p384key);
