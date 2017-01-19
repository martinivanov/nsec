# SignatureAlgorithm Class

Represents a digital signature algorithm.

    public abstract class SignatureAlgorithm : Algorithm


## Inheritance Hierarchy

* [[Algorithm|Algorithm Class]]
    * **SignatureAlgorithm**
        * Ed25519


## [TOC] Summary


## Properties


### PrivateKeySize

Gets the private size, in bytes.

    public int PrivateKeySize { get; }

#### Property value

The private key size, in bytes.


### PublicKeySize

Gets the public key size, in bytes.

    public int PublicKeySize { get; }

#### Property value

The public key size, in bytes.


### SignatureSize

Gets the signature size, in bytes.

    public int SignatureSize { get; }

#### Property value

The signature size, in bytes.


## Methods


### Sign(Key, ReadOnlySpan<byte>)

Signs the specified input data using the specified key and returns the signature
as an array of bytes.

    public byte[] Sign(
        Key key,
        ReadOnlySpan<byte> data)

#### Parameters

key
: The [[Key|Key Class]] object to use for signing.

data
: The data to be signed.

#### Return value

The data's signature.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[SignatureAlgorithm|SignatureAlgorithm Class]] object.

ObjectDisposedException
: `key` has been disposed.


### Sign(Key, ReadOnlySpan<byte>, Span<byte>)

Signs the specified input data using the specified key and fills the specified
span of bytes with the signature.

    public void Sign(
        Key key,
        ReadOnlySpan<byte> data,
        Span<byte> signature)

#### Parameters

key
: The [[Key|Key Class]] object to use for signing.

data
: The data to be signed.

signature
: The span to fill with the signature.

#### Exceptions

ArgumentNullException
: `key` is `null`.

ArgumentException
: `key.Algorithm` is not the same object as the current
    [[SignatureAlgorithm|SignatureAlgorithm Class]] object.

ArgumentException
: The length of `signature` is not equal to the value of
    [[SignatureSize|SignatureAlgorithm Class#SignatureSize]].

ObjectDisposedException
: `key` has been disposed.


### TryVerify(PublicKey, ReadOnlySpan<byte>, ReadOnlySpan<byte>)

Attempts to verify the signature of the specified input data using the specified
public key.

    public bool TryVerify(
        PublicKey publicKey,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)

#### Parameters

publicKey
: The [[PublicKey|PublicKey Class]] object to use for verification. This must
    be the public key for the key previously used to sign the input data.

data
: The data to be verified.

signature
: The signature to be verified.

#### Return value

`true` if verification succeeds; otherwise, `false`.

#### Exceptions

ArgumentNullException
: `publicKey` is `null`.

ArgumentException
: `publicKey.Algorithm` is not the same object as the current
    [[SignatureAlgorithm|SignatureAlgorithm Class]] object.


### Verify(PublicKey, ReadOnlySpan<byte>, ReadOnlySpan<byte>)

Verifies the signature of the specified input data using the specified public
key.

    public void Verify(
        PublicKey publicKey,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)

#### Parameters

publicKey
: The [[PublicKey|PublicKey Class]] object to use for verification. This must
    be the public key for the key previously used to sign the input data.

data
: The data to be verified.

signature
: The signature to be verified.

#### Exceptions

ArgumentNullException
: `publicKey` is `null`.

ArgumentException
: `publicKey.Algorithm` is not the same object as the current
    [[SignatureAlgorithm|SignatureAlgorithm Class]] object.

CryptographicException
: Verification failed.


## See also

* API Reference
    * [[Algorithm Class]]
    * [[Key Class]]
    * [[PublicKey Class]]